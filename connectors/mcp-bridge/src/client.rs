//! MCP JSON-RPC client over HTTP (Streamable HTTP transport).

use fcp_manifest::{
    Base64Bytes, HostEgressContext, HostEgressDecisionMetadata, HostEgressHttpHeader,
    HostEgressHttpRequest,
};
use fcp_prelude::CredentialId;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_async_core::sync::Mutex;
use fcp_sdk::migration::HostEgressProxyError;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode, Url, header::HeaderMap};
use serde_json::json;
use tracing::instrument;

use crate::{
    error::{McpBridgeError, McpBridgeResult},
    protocol::{
        ClientCapabilities, ClientInfo, HttpHeaderPlan, LegacySession, McpMethod,
        Modern400Decision, ProtocolEra, ProtocolVersion, classify_modern_400,
        inject_modern_metadata, legacy_initialize_request, legacy_initialized_notification,
        parse_legacy_initialize_response, parse_response,
    },
    types::JsonRpcRequest,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// MCP server authentication.
#[derive(Clone)]
pub struct McpAuth {
    pub api_key: Option<String>,
    pub credential_id: Option<CredentialId>,
}

impl McpAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        if self.api_key.is_some() {
            "api_key:redacted".to_string()
        } else if self.credential_id.is_some() {
            "credential_id:redacted".to_string()
        } else {
            "none".to_string()
        }
    }
}

impl fmt::Debug for McpAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpAuth")
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// MCP JSON-RPC client that communicates with an MCP server over HTTP.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct McpClientMetrics {
    pub auth_retry_count: u64,
    pub session_expired_retry_count: u64,
}

pub struct McpClient {
    client: Client,
    auth: McpAuth,
    base_url: Url,
    request_id: AtomicU64,
    runtime: ConnectorRuntime,
    auth_retry_count: AtomicU64,
    session_expired_retry_count: AtomicU64,
    legacy_session: Mutex<Option<LegacySession>>,
}

struct RawResponse {
    request_id: u64,
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl fmt::Debug for McpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl McpClient {
    /// Create a new MCP client.
    ///
    /// The URL is retained for explicit legacy/test compatibility and as the
    /// mediated provider target. Direct HTTP is allowed only for canonical
    /// loopback test URLs; production credential traffic uses host egress.
    pub fn new(auth: McpAuth, base_url: &str) -> McpBridgeResult<Self> {
        // Presence-only conflict detection keeps the legacy URL out of the
        // production runtime config while failing closed if launchers provide
        // both transport selectors.
        if std::env::var_os("FCP_HOST_EGRESS_TRANSPORT").is_some()
            && std::env::var_os("FCP_HOST_EGRESS_PROXY_URL").is_some()
        {
            return Err(McpBridgeError::InvalidInput(
                "conflicting host egress transport configuration".into(),
            ));
        }
        let runtime_config = ConnectorRuntimeConfig::default()
            .with_request_timeout(REQUEST_TIMEOUT)
            .with_host_egress_from_env()
            .map_err(|_| {
                McpBridgeError::InvalidInput("invalid host egress launch configuration".into())
            })?;
        let client = Client::builder()
            .connect_timeout(runtime_config.connect_timeout)
            .timeout(runtime_config.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent("fcp-mcp-bridge/0.1.0 (FCP connector)")
            .build()?;

        if auth.api_key.is_some() && auth.credential_id.is_some() {
            return Err(McpBridgeError::InvalidInput(
                "provide exactly one MCP authentication method".into(),
            ));
        }
        let url = Self::canonicalize_base_url(base_url)?;

        Ok(Self {
            client,
            auth,
            base_url: url,
            request_id: AtomicU64::new(1),
            runtime: ConnectorRuntime::new(runtime_config),
            auth_retry_count: AtomicU64::new(0),
            session_expired_retry_count: AtomicU64::new(0),
            legacy_session: Mutex::new(None),
        })
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::Relaxed)
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref key) = self.auth.api_key {
            req.header("Authorization", format!("Bearer {key}"))
        } else {
            req
        }
    }

    /// Snapshot retry/session metrics.
    #[must_use]
    pub fn metrics(&self) -> McpClientMetrics {
        McpClientMetrics {
            auth_retry_count: self.auth_retry_count.load(Ordering::Relaxed),
            session_expired_retry_count: self.session_expired_retry_count.load(Ordering::Relaxed),
        }
    }

    /// Return the validated protocol profile established by the latest
    /// successful discovery path. Modern is the default before any legacy
    /// fallback session has been negotiated.
    pub(crate) async fn negotiated_profile(&self) -> (ProtocolEra, ProtocolVersion) {
        self.legacy_session.lock().await.as_ref().map_or(
            (ProtocolEra::Modern, ProtocolVersion::V20260728),
            |session| (session.protocol_version.era(), session.protocol_version),
        )
    }

    /// Send a JSON-RPC request to the MCP server.
    #[instrument(skip(self, params), fields(mcp_method))]
    /// Issue an MCP JSON-RPC call.
    ///
    /// Replay safety is derived from the MCP method: the discovery and read
    /// methods are pure reads, while `tools/call` invokes an arbitrary
    /// downstream tool whose effects this bridge cannot see (br-kxd3e).
    pub async fn rpc_call(
        &self,
        mcp_method: &str,
        params: serde_json::Value,
    ) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call_with_context(mcp_method, params, None).await
    }

    async fn rpc_call_with_context(
        &self,
        mcp_method: &str,
        params: serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> McpBridgeResult<serde_json::Value> {
        let method = typed_method(mcp_method)?;
        if is_read_method(method) {
            let mut legacy_session = self.legacy_session.lock().await;
            if let Some(session) = legacy_session.clone() {
                return self
                    .legacy_read_with_retry(method, &params, context, &mut legacy_session, session)
                    .await;
            }

            let modern = self
                .send_request(
                    method,
                    ProtocolVersion::V20260728,
                    None,
                    params.clone(),
                    context.clone(),
                    true,
                )
                .await?;
            if modern.status.is_success() {
                return decode_raw_response(&modern);
            }
            if modern.status != StatusCode::BAD_REQUEST {
                return map_raw_status(&modern);
            }
            match classify_modern_400(&modern.body) {
                Modern400Decision::Recognized { .. } => {
                    return Err(McpBridgeError::Api {
                        status_code: 400,
                        message: "MCP modern protocol correction is required".into(),
                    });
                }
                Modern400Decision::LegacyFallback => {
                    let session = self.initialize_legacy(context.clone()).await?;
                    let result = self
                        .legacy_read_with_retry(
                            method,
                            &params,
                            context,
                            &mut legacy_session,
                            session,
                        )
                        .await?;
                    return Ok(result);
                }
            }
        }

        let response = self
            .send_request(
                method,
                ProtocolVersion::V20260728,
                None,
                params,
                context,
                true,
            )
            .await?;
        decode_raw_response(&response)
    }

    async fn send_request(
        &self,
        method: McpMethod,
        version: ProtocolVersion,
        session: Option<&LegacySession>,
        mut params: serde_json::Value,
        context: Option<HostEgressContext>,
        modern: bool,
    ) -> McpBridgeResult<RawResponse> {
        let id = self.next_id();
        if modern {
            inject_modern_metadata(
                &mut params,
                &ClientInfo::new("fcp-mcp-bridge", "0.1.0").map_err(|_| {
                    McpBridgeError::InvalidInput("invalid MCP client metadata".into())
                })?,
                ClientCapabilities::default(),
            )
            .map_err(|_| McpBridgeError::InvalidInput("invalid MCP request metadata".into()))?;
        } else if let Some(object) = params.as_object_mut() {
            object.remove("_meta");
        }
        let name = match method {
            McpMethod::ResourcesRead => params.get("uri").and_then(serde_json::Value::as_str),
            McpMethod::ToolsCall | McpMethod::PromptsGet => {
                params.get("name").and_then(serde_json::Value::as_str)
            }
            _ => None,
        };
        let header_plan = if let Some(session) = session {
            session
                .headers(method, name)
                .map_err(|_| McpBridgeError::InvalidInput("invalid MCP request headers".into()))?
        } else {
            HttpHeaderPlan::for_request(version, method, name, None)
                .map_err(|_| McpBridgeError::InvalidInput("invalid MCP request headers".into()))?
        };
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.as_str().to_string(),
            params,
        };
        let body = serde_json::to_vec(&request).map_err(|_| {
            McpBridgeError::InvalidInput("MCP request could not be serialized".into())
        })?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(McpBridgeError::InvalidInput(
                "MCP request exceeds the configured size limit".into(),
            ));
        }
        let mut headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "Accept".to_string(),
                "application/json, text/event-stream".to_string(),
            ),
        ];
        headers.extend(
            header_plan
                .header_pairs()
                .into_iter()
                .map(|(name, value)| (name.to_string(), value)),
        );
        self.send_raw(id, &headers, &body, context).await
    }

    async fn send_raw(
        &self,
        request_id: u64,
        headers: &[(String, String)],
        body: &[u8],
        context: Option<HostEgressContext>,
    ) -> McpBridgeResult<RawResponse> {
        match (&self.auth, context) {
            (
                McpAuth {
                    credential_id: Some(_),
                    ..
                },
                Some(context),
            ) => {
                self.send_raw_mediated(request_id, headers, body, context)
                    .await
            }
            (
                McpAuth {
                    credential_id: Some(_),
                    ..
                },
                None,
            ) => Err(McpBridgeError::InvalidInput(
                "credential_id requires verified request attribution".into(),
            )),
            (
                McpAuth {
                    credential_id: None,
                    ..
                },
                _,
            ) => self.send_raw_direct(request_id, headers, body).await,
        }
    }

    async fn send_raw_direct(
        &self,
        request_id: u64,
        headers: &[(String, String)],
        body: &[u8],
    ) -> McpBridgeResult<RawResponse> {
        self.ensure_provider_egress_allowed()?;
        let mut request = self.add_auth(self.client.post(self.base_url.clone()));
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let response =
            request
                .body(body.to_vec())
                .send()
                .await
                .map_err(|_| McpBridgeError::Api {
                    status_code: 502,
                    message: "MCP provider transport failed".into(),
                })?;
        let status = response.status();
        let headers = collect_response_headers(response.headers())?;
        let body = read_bounded_body(response).await?;
        Ok(RawResponse {
            request_id,
            status,
            headers,
            body,
        })
    }

    async fn send_raw_mediated(
        &self,
        request_id: u64,
        headers: &[(String, String)],
        body: &[u8],
        context: HostEgressContext,
    ) -> McpBridgeResult<RawResponse> {
        let Some(credential_id) = self.auth.credential_id else {
            return Err(McpBridgeError::InvalidInput(
                "host-mediated egress requires credential_id auth".into(),
            ));
        };
        let proxy = self
            .runtime
            .host_egress_proxy_client()
            .map_err(|_| {
                McpBridgeError::InvalidInput(
                    "trusted host egress proxy configuration is invalid".into(),
                )
            })?
            .ok_or_else(|| {
                McpBridgeError::InvalidInput(
                    "credential_id requires the trusted host egress proxy configuration".into(),
                )
            })?;
        let request_headers = headers
            .iter()
            .map(|(name, value)| HostEgressHttpHeader {
                name: name.clone(),
                value: value.clone(),
            })
            .collect();
        let proxy_request = HostEgressHttpRequest {
            context: context.clone(),
            url: self.base_url.to_string(),
            method: "POST".into(),
            headers: request_headers,
            body: Some(Base64Bytes::from_vec(body.to_vec())),
            credential_id: Some(credential_id.to_string()),
        };
        let response = proxy
            .http(&proxy_request)
            .await
            .map_err(|error| map_host_egress_error(&error))?;
        validate_host_egress_decision(&response.egress, &context, &self.base_url)?;
        let status = StatusCode::from_u16(response.status).map_err(|_| McpBridgeError::Api {
            status_code: 502,
            message: "host egress proxy returned an invalid status".into(),
        })?;
        if response.body.as_bytes().len() > crate::protocol::MAX_RESPONSE_BYTES {
            return Err(McpBridgeError::Api {
                status_code: 502,
                message: "MCP provider response exceeded the configured size limit".into(),
            });
        }
        Ok(RawResponse {
            request_id,
            status,
            headers: response
                .headers
                .into_iter()
                .map(|header| (header.name, header.value))
                .collect(),
            body: response.body.as_bytes().to_vec(),
        })
    }

    async fn initialize_legacy(
        &self,
        context: Option<HostEgressContext>,
    ) -> McpBridgeResult<LegacySession> {
        let request_id = self.next_id();
        let request = legacy_initialize_request(
            request_id,
            ProtocolVersion::V20251125,
            ClientInfo::new("fcp-mcp-bridge", "0.1.0")
                .map_err(|_| McpBridgeError::InvalidInput("invalid MCP client metadata".into()))?,
            ClientCapabilities::default(),
        )
        .map_err(|_| {
            McpBridgeError::InvalidInput("invalid legacy MCP initialize request".into())
        })?;
        let body = serde_json::to_vec(&request).map_err(|_| {
            McpBridgeError::InvalidInput("MCP initialize request could not be serialized".into())
        })?;
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "Accept".to_string(),
                "application/json, text/event-stream".to_string(),
            ),
        ];
        let response = self
            .send_raw(request_id, &headers, &body, context.clone())
            .await?;
        if !response.status.is_success() {
            return Err(raw_status_error(&response)?);
        }
        let content_type = single_header(&response.headers, "content-type")?.ok_or_else(|| {
            McpBridgeError::Api {
                status_code: 502,
                message: "MCP initialize response had invalid content type".into(),
            }
        })?;
        if content_media_type(&content_type) != "application/json" {
            return Err(McpBridgeError::Api {
                status_code: 502,
                message: "MCP initialize response had invalid content type".into(),
            });
        }
        let value: serde_json::Value =
            serde_json::from_slice(&response.body).map_err(|_| McpBridgeError::Api {
                status_code: 502,
                message: "MCP initialize response was malformed".into(),
            })?;
        let session_header = single_header(&response.headers, "mcp-session-id")?;
        let initialized =
            parse_legacy_initialize_response(&value, request_id, session_header.as_deref())
                .map_err(|_| McpBridgeError::Api {
                    status_code: 502,
                    message: "MCP initialize response was invalid".into(),
                })?;
        let session = initialized.session;

        let notification_id = self.next_id();
        let notification = legacy_initialized_notification();
        let body = serde_json::to_vec(&notification).map_err(|_| {
            McpBridgeError::InvalidInput(
                "MCP initialized notification could not be serialized".into(),
            )
        })?;
        let plan = session
            .headers(McpMethod::Initialized, None)
            .map_err(|_| McpBridgeError::InvalidInput("invalid legacy MCP headers".into()))?;
        let response = self
            .send_raw(notification_id, &protocol_headers(&plan), &body, context)
            .await?;
        if response.status != StatusCode::ACCEPTED || !response.body.is_empty() {
            return Err(McpBridgeError::Api {
                status_code: response.status.as_u16(),
                message: "MCP initialized notification was not accepted".into(),
            });
        }
        Ok(session)
    }

    async fn legacy_read_with_retry(
        &self,
        method: McpMethod,
        params: &serde_json::Value,
        context: Option<HostEgressContext>,
        legacy_session: &mut Option<LegacySession>,
        session: LegacySession,
    ) -> McpBridgeResult<serde_json::Value> {
        *legacy_session = Some(session.clone());
        let response = self
            .send_request(
                method,
                session.protocol_version,
                Some(&session),
                params.clone(),
                context.clone(),
                false,
            )
            .await?;
        if response.status != StatusCode::NOT_FOUND || session.session_id.is_none() {
            return decode_raw_response(&response);
        }

        legacy_session.take();
        self.session_expired_retry_count
            .fetch_add(1, Ordering::Relaxed);
        let refreshed = self.initialize_legacy(context.clone()).await?;
        *legacy_session = Some(refreshed.clone());
        let response = self
            .send_request(
                method,
                refreshed.protocol_version,
                Some(&refreshed),
                params.clone(),
                context,
                false,
            )
            .await?;
        if response.status == StatusCode::NOT_FOUND {
            legacy_session.take();
        }
        decode_raw_response(&response)
    }

    /// Canonicalize an exact MCP Streamable HTTP endpoint.
    ///
    /// Loopback HTTP is the explicit legacy/test direct transport. Remote
    /// HTTPS URLs are accepted only as host-mediated targets.
    pub fn canonicalize_base_url(base_url: &str) -> McpBridgeResult<Url> {
        let mut parsed = Url::parse(base_url.trim())
            .map_err(|_| McpBridgeError::InvalidInput("mcp_url must be an absolute URL".into()))?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(McpBridgeError::InvalidInput(
                "mcp_url must not contain userinfo".into(),
            ));
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(McpBridgeError::InvalidInput(
                "mcp_url must not contain query or fragment".into(),
            ));
        }
        let Some(host) = parsed.host_str() else {
            return Err(McpBridgeError::InvalidInput(
                "mcp_url must include a host".into(),
            ));
        };
        let local = is_loopback_host(host);
        match parsed.scheme() {
            "http" if local => {}
            "https" if !local => {}
            "https" => {
                return Err(McpBridgeError::InvalidInput(
                    "localhost MCP endpoints are test-only and must use loopback HTTP".into(),
                ));
            }
            _ => {
                return Err(McpBridgeError::InvalidInput(
                    "mcp_url must use HTTPS for production or HTTP only for loopback tests".into(),
                ));
            }
        }
        if !local && (is_ip_literal(host) || is_private_hostname(host)) {
            return Err(McpBridgeError::InvalidInput(
                "mcp_url must not target private, tailnet, localhost, or IP-literal production hosts".into(),
            ));
        }
        if !local && parsed.port().is_some_and(|port| port != 443) {
            return Err(McpBridgeError::InvalidInput(
                "mcp_url must use production HTTPS port 443".into(),
            ));
        }
        let path = parsed.path();
        if path.contains('%') || !matches!(path, "/mcp" | "/mcp/") {
            return Err(McpBridgeError::InvalidInput(
                "mcp_url must be the exact /mcp endpoint; only a trailing slash may be normalized"
                    .into(),
            ));
        }
        parsed.set_path("/mcp");
        parsed.set_query(None);
        parsed.set_fragment(None);
        if parsed.port() == Some(443) {
            parsed.set_port(None).map_err(|()| {
                McpBridgeError::InvalidInput("mcp_url port could not be canonicalized".into())
            })?;
        }
        Ok(parsed)
    }

    fn ensure_provider_egress_allowed(&self) -> McpBridgeResult<()> {
        if self.auth.credential_id.is_some() {
            return Err(McpBridgeError::InvalidInput(
                "credential_id requires host-mediated secret injection; direct MCP egress is unavailable".into(),
            ));
        }
        if !self.base_url.host_str().is_some_and(is_loopback_host) {
            return Err(McpBridgeError::InvalidInput(
                "production MCP egress requires host-mediated exact-origin enforcement".into(),
            ));
        }
        Ok(())
    }

    // -- MCP Operations --

    /// List tools from the MCP server.
    pub async fn tools_list(&self) -> McpBridgeResult<serde_json::Value> {
        self.tools_list_with_context(None).await
    }

    pub(crate) async fn tools_list_with_context(
        &self,
        context: Option<HostEgressContext>,
    ) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call_with_context("tools/list", json!({}), context)
            .await
    }

    /// Call a tool on a literal-loopback MCP endpoint.
    ///
    /// This direct helper is retained only for legacy/test compatibility. A
    /// production call must use [`Self::tools_call_with_context`] so the
    /// verified host-egress attribution travels with the request.
    pub async fn tools_call(
        &self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> McpBridgeResult<serde_json::Value> {
        self.tools_call_inner(name, arguments, None).await
    }

    /// Call a tool with verified host-egress attribution.
    pub(crate) async fn tools_call_with_context(
        &self,
        name: &str,
        arguments: &serde_json::Value,
        context: HostEgressContext,
    ) -> McpBridgeResult<serde_json::Value> {
        self.tools_call_inner(name, arguments, Some(context)).await
    }

    async fn tools_call_inner(
        &self,
        name: &str,
        arguments: &serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> McpBridgeResult<serde_json::Value> {
        let params = tools_call_params(name, arguments)?;
        let mut legacy_session = self.legacy_session.lock().await;
        if let Some(session) = legacy_session.clone() {
            let response = self
                .send_request(
                    McpMethod::ToolsCall,
                    session.protocol_version,
                    Some(&session),
                    params,
                    context.clone(),
                    false,
                )
                .await?;
            if response.status == StatusCode::NOT_FOUND {
                legacy_session.take();
            }
            return decode_raw_response(&response);
        }
        drop(legacy_session);

        let response = self
            .send_request(
                McpMethod::ToolsCall,
                ProtocolVersion::V20260728,
                None,
                params,
                context,
                true,
            )
            .await?;
        decode_raw_response(&response)
    }

    /// List resources from the MCP server.
    pub async fn resources_list(&self) -> McpBridgeResult<serde_json::Value> {
        self.resources_list_with_context(None).await
    }

    pub(crate) async fn resources_list_with_context(
        &self,
        context: Option<HostEgressContext>,
    ) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call_with_context("resources/list", json!({}), context)
            .await
    }

    /// Read a resource from the MCP server.
    pub async fn resources_read(&self, uri: &str) -> McpBridgeResult<serde_json::Value> {
        self.resources_read_with_context(uri, None).await
    }

    pub(crate) async fn resources_read_with_context(
        &self,
        uri: &str,
        context: Option<HostEgressContext>,
    ) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call_with_context("resources/read", json!({"uri": uri}), context)
            .await
    }

    /// List prompts from the MCP server.
    pub async fn prompts_list(&self) -> McpBridgeResult<serde_json::Value> {
        self.prompts_list_with_context(None).await
    }

    pub(crate) async fn prompts_list_with_context(
        &self,
        context: Option<HostEgressContext>,
    ) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call_with_context("prompts/list", json!({}), context)
            .await
    }
}

fn typed_method(method: &str) -> McpBridgeResult<McpMethod> {
    match method {
        "tools/list" => Ok(McpMethod::ToolsList),
        "tools/call" => Ok(McpMethod::ToolsCall),
        "resources/list" => Ok(McpMethod::ResourcesList),
        "resources/read" => Ok(McpMethod::ResourcesRead),
        "prompts/list" => Ok(McpMethod::PromptsList),
        "prompts/get" => Ok(McpMethod::PromptsGet),
        _ => Err(McpBridgeError::InvalidInput(
            "unsupported MCP method".into(),
        )),
    }
}

fn tools_call_params(
    name: &str,
    arguments: &serde_json::Value,
) -> McpBridgeResult<serde_json::Value> {
    if name.is_empty() || name.len() > crate::protocol::MAX_PUBLIC_ID_BYTES {
        return Err(McpBridgeError::InvalidInput(
            "MCP tool name must be non-empty and within the configured size limit".into(),
        ));
    }
    if !arguments.is_object() {
        return Err(McpBridgeError::InvalidInput(
            "MCP tool arguments must be an object".into(),
        ));
    }
    Ok(json!({
        "name": name,
        "arguments": arguments,
    }))
}

const fn is_read_method(method: McpMethod) -> bool {
    matches!(
        method,
        McpMethod::ToolsList
            | McpMethod::ResourcesList
            | McpMethod::ResourcesRead
            | McpMethod::PromptsList
    )
}

fn protocol_headers(plan: &HttpHeaderPlan) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        (
            "Accept".to_string(),
            "application/json, text/event-stream".to_string(),
        ),
    ];
    headers.extend(
        plan.header_pairs()
            .into_iter()
            .map(|(name, value)| (name.to_string(), value)),
    );
    headers
}

fn collect_response_headers(headers: &HeaderMap) -> McpBridgeResult<Vec<(String, String)>> {
    headers
        .iter()
        .map(|(name, value)| {
            let value = value.to_str().map_err(|_| McpBridgeError::Api {
                status_code: 502,
                message: "MCP provider returned invalid response headers".into(),
            })?;
            Ok((name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect()
}

fn single_header(headers: &[(String, String)], name: &str) -> McpBridgeResult<Option<String>> {
    let matches: Vec<_> = headers
        .iter()
        .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
        .collect();
    match matches.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(value.clone())),
        _ => Err(McpBridgeError::Api {
            status_code: 502,
            message: "MCP provider returned duplicate response headers".into(),
        }),
    }
}

fn decode_raw_response(response: &RawResponse) -> McpBridgeResult<serde_json::Value> {
    if !response.status.is_success() {
        return map_raw_status(response);
    }
    let content_type =
        single_header(&response.headers, "content-type")?.ok_or_else(|| McpBridgeError::Api {
            status_code: 502,
            message: "MCP provider returned an invalid content type".into(),
        })?;
    decode_rpc_response(&content_type, &response.body, response.request_id)
}

fn map_raw_status(response: &RawResponse) -> McpBridgeResult<serde_json::Value> {
    Err(raw_status_error(response)?)
}

fn raw_status_error(response: &RawResponse) -> McpBridgeResult<McpBridgeError> {
    let retry_after = single_header(&response.headers, "retry-after")?
        .and_then(|value| value.parse::<u64>().ok());
    Ok(map_provider_status(response.status.as_u16(), retry_after))
}

fn response_content_type(headers: &HeaderMap) -> McpBridgeResult<String> {
    let values: Vec<_> = headers.get_all("content-type").iter().collect();
    if values.len() != 1 {
        return Err(McpBridgeError::Api {
            status_code: 502,
            message: "MCP provider returned an invalid content type".into(),
        });
    }
    values[0]
        .to_str()
        .map(normalize_content_type)
        .map_err(|_| McpBridgeError::Api {
            status_code: 502,
            message: "MCP provider returned an invalid content type".into(),
        })
}

async fn read_bounded_body(mut response: Response) -> McpBridgeResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > crate::protocol::MAX_RESPONSE_BYTES as u64)
    {
        return Err(McpBridgeError::Api {
            status_code: 502,
            message: "MCP provider response exceeded the configured size limit".into(),
        });
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(crate::protocol::MAX_RESPONSE_BYTES),
    );
    while let Some(chunk) = response.chunk().await.map_err(|_| McpBridgeError::Api {
        status_code: 502,
        message: "MCP provider response could not be read".into(),
    })? {
        if chunk.len() > crate::protocol::MAX_RESPONSE_BYTES.saturating_sub(body.len()) {
            return Err(McpBridgeError::Api {
                status_code: 502,
                message: "MCP provider response exceeded the configured size limit".into(),
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn decode_rpc_response(
    content_type: &str,
    body: &[u8],
    request_id: u64,
) -> McpBridgeResult<serde_json::Value> {
    let normalized_content_type = normalize_content_type(content_type);
    let parsed = parse_response(&normalized_content_type, body, request_id).map_err(|_| {
        McpBridgeError::Api {
            status_code: 502,
            message: "MCP provider returned a malformed response".into(),
        }
    })?;
    if let Some(error) = parsed.error {
        return Err(McpBridgeError::McpError {
            code: error.code,
            message: "MCP JSON-RPC provider error".into(),
        });
    }
    Ok(parsed.result.unwrap_or(serde_json::Value::Null))
}

fn normalize_content_type(value: &str) -> String {
    let mut parts = value.splitn(2, ';');
    let media_type = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
    match parts.next() {
        Some(parameters) => format!("{media_type};{parameters}"),
        None => media_type,
    }
}

fn content_media_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn map_provider_status(status: u16, retry_after: Option<u64>) -> McpBridgeError {
    match status {
        401 => McpBridgeError::Unauthorized,
        403 => McpBridgeError::Forbidden,
        404 => McpBridgeError::NotFound {
            resource: "MCP endpoint".into(),
        },
        429 => McpBridgeError::RateLimited {
            retry_after_ms: retry_after.unwrap_or(60).saturating_mul(1000),
        },
        code => McpBridgeError::Api {
            status_code: code,
            message: "MCP provider returned an HTTP error".into(),
        },
    }
}

fn map_host_egress_error(error: &HostEgressProxyError) -> McpBridgeError {
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
    McpBridgeError::Api {
        status_code: 502,
        message: message.into(),
    }
}

fn validate_host_egress_decision(
    decision: &HostEgressDecisionMetadata,
    context: &HostEgressContext,
    target: &Url,
) -> McpBridgeResult<()> {
    let expected_host = target.host_str().ok_or_else(|| McpBridgeError::Api {
        status_code: 502,
        message: "host egress proxy returned an invalid decision".into(),
    })?;
    let expected_port = target
        .port_or_known_default()
        .ok_or_else(|| McpBridgeError::Api {
            status_code: 502,
            message: "host egress proxy returned an invalid decision".into(),
        })?;
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
        return Err(McpBridgeError::Api {
            status_code: 502,
            message: "host egress proxy returned an invalid decision".into(),
        });
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

fn is_private_hostname(host: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized.strip_suffix(".local").is_some()
        || normalized.strip_suffix(".internal").is_some()
        || normalized.strip_suffix(".home.arpa").is_some()
        || normalized.strip_suffix(".ts.net").is_some()
        || normalized.strip_suffix(".tailnet").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex as StdMutex};

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    struct SequenceResponder(Arc<StdMutex<VecDeque<ResponseTemplate>>>);

    impl SequenceResponder {
        fn new(responses: Vec<ResponseTemplate>) -> Self {
            Self(Arc::new(StdMutex::new(VecDeque::from(responses))))
        }
    }

    impl Respond for SequenceResponder {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            self.0
                .lock()
                .expect("sequence responder mutex poisoned")
                .pop_front()
                .unwrap_or_else(|| ResponseTemplate::new(599))
        }
    }

    fn test_transport_error(_: &Request) -> std::io::Error {
        std::io::Error::other("test transport failure")
    }

    async fn mount_sequence(server: &MockServer, responses: Vec<ResponseTemplate>) {
        Mock::given(method("POST"))
            .and(path("/mcp"))
            .respond_with(SequenceResponder::new(responses))
            .mount(server)
            .await;
    }

    fn loopback_client(server: &MockServer) -> McpClient {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let url = format!("{}/mcp", server.uri());
        McpClient::new(auth, &url).expect("wiremock loopback URL should be accepted")
    }

    fn test_context() -> HostEgressContext {
        HostEgressContext {
            connector_id: "fcp.mcp-bridge".into(),
            operation_id: "mcp.tools.call".into(),
            resource_uri: "fcp://mcp/server/tool".into(),
            zone_id: "z:private".into(),
            request_id: "session:1".into(),
            correlation_id: None,
            capability_token_cbor_b64: "token".into(),
        }
    }

    fn rpc_response(status: u16, id: u64, result: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(status).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }))
    }

    fn initialize_response(id: u64, session_id: Option<&str>) -> ResponseTemplate {
        let mut response = rpc_response(
            200,
            id,
            json!({
                "protocolVersion": "2025-11-25",
                "serverInfo": {"name": "wiremock", "version": "1"},
                "capabilities": {"tools": {}}
            }),
        );
        if let Some(session_id) = session_id {
            response = response.insert_header("Mcp-Session-Id", session_id);
        }
        response
    }

    fn request_json(request: &Request) -> serde_json::Value {
        serde_json::from_slice(&request.body).expect("wiremock request should be JSON")
    }

    fn request_methods(requests: &[Request]) -> Vec<String> {
        requests
            .iter()
            .map(|request| {
                request_json(request)["method"]
                    .as_str()
                    .expect("JSON-RPC method")
                    .to_string()
            })
            .collect()
    }

    fn header(request: &Request, name: &str) -> Option<String> {
        request
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    }

    fn has_header(request: &Request, name: &str) -> bool {
        request.headers.contains_key(name)
    }

    #[test]
    fn auth_debug_redacts_key() {
        let auth = McpAuth {
            api_key: Some("secret-key-value".into()),
            credential_id: None,
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-key-value"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_debug_none_key() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("None"));
    }

    #[test]
    fn auth_redacted_label_with_key() {
        let auth = McpAuth {
            api_key: Some("secret".into()),
            credential_id: None,
        };
        let label = auth.redacted_label();
        assert!(label.contains("redacted"));
        assert!(!label.contains("secret"));
    }

    #[test]
    fn auth_redacted_label_without_key() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let label = auth.redacted_label();
        assert!(label.contains("none"));
    }

    #[test]
    fn client_new_with_url() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://mcp.example.com/mcp").unwrap();
        assert_eq!(client.base_url.as_str(), "https://mcp.example.com/mcp");
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://mcp.example.com/mcp/").unwrap();
        assert_eq!(client.base_url.as_str(), "https://mcp.example.com/mcp");
    }

    #[test]
    fn client_debug_shows_base_url() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://example.com/mcp").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("example.com"));
    }

    #[test]
    fn client_debug_does_not_leak_key() {
        let auth = McpAuth {
            api_key: Some("super-secret".into()),
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://example.com/mcp").unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn auth_clone() {
        let auth = McpAuth {
            api_key: Some("KEY".into()),
            credential_id: None,
        };
        let cloned = McpAuth::clone(&auth);
        assert_eq!(cloned.api_key, Some("KEY".into()));
    }

    #[test]
    fn auth_clone_none() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let cloned = McpAuth::clone(&auth);
        assert!(cloned.api_key.is_none());
    }

    #[test]
    fn next_id_increments() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://example.com/mcp").unwrap();
        let id1 = client.next_id();
        let id2 = client.next_id();
        let id3 = client.next_id();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn next_id_starts_at_one() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://example.com/mcp").unwrap();
        assert_eq!(client.next_id(), 1);
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://example.com/mcp").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("McpClient"));
    }

    #[test]
    fn auth_debug_contains_struct_name() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("McpAuth"));
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://example.com/mcp/").unwrap();
        assert_eq!(client.base_url.path(), "/mcp");
    }

    #[test]
    fn auth_redacted_label_with_some_key() {
        let auth = McpAuth {
            api_key: Some("key".into()),
            credential_id: None,
        };
        assert_eq!(auth.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_redacted_label_with_none_key() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        assert_eq!(auth.redacted_label(), "none");
    }

    #[test]
    fn auth_redacted_label_hides_credential_reference() {
        let auth = McpAuth {
            api_key: None,
            credential_id: Some(CredentialId::new()),
        };
        assert_eq!(auth.redacted_label(), "credential_id:redacted");
    }

    #[test]
    fn client_new_with_localhost_port() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "http://127.0.0.1:3000/mcp").unwrap();
        assert_eq!(client.base_url.as_str(), "http://127.0.0.1:3000/mcp");
    }

    #[test]
    fn auth_debug_some_key_shows_redacted() {
        let auth = McpAuth {
            api_key: Some("my-super-secret-key".into()),
            credential_id: None,
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("my-super-secret-key"));
    }

    #[test]
    fn client_new_rejects_non_mcp_path() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        assert!(McpClient::new(auth, "https://example.com/api/v1").is_err());
    }

    #[test]
    fn modern_request_has_metadata_and_typed_headers() {
        let mut params = json!({"uri": "mcp://server/a b"});
        inject_modern_metadata(
            &mut params,
            &ClientInfo::new("fcp-mcp-bridge", "0.1.0").unwrap(),
            ClientCapabilities::default(),
        )
        .unwrap();
        let plan = HttpHeaderPlan::for_request(
            ProtocolVersion::V20260728,
            McpMethod::ResourcesRead,
            params["uri"].as_str(),
            None,
        )
        .unwrap();
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 7,
            method: "resources/read".into(),
            params,
        };
        let body = serde_json::to_vec(&request).unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("io.modelcontextprotocol/protocolVersion"));
        assert!(text.contains("io.modelcontextprotocol/clientCapabilities"));
        assert!(text.contains("\"id\":7"));
        let headers = plan.header_pairs();
        assert!(
            headers
                .iter()
                .any(|(name, value)| { *name == "Mcp-Method" && value == "resources/read" })
        );
        assert!(headers.iter().any(|(name, _)| *name == "Mcp-Name"));
    }

    #[test]
    fn production_direct_transport_is_denied() {
        let client = McpClient::new(
            McpAuth {
                api_key: Some("secret".into()),
                credential_id: None,
            },
            "https://provider.example/mcp",
        )
        .unwrap();
        let error = client.ensure_provider_egress_allowed().unwrap_err();
        assert!(error.safe_summary().contains("host-mediated"));
        assert!(!error.safe_summary().contains("secret"));
    }

    #[fcp_async_core::runtime::test]
    async fn credential_transport_requires_verified_context() {
        let client = McpClient::new(
            McpAuth {
                api_key: None,
                credential_id: Some(CredentialId::new()),
            },
            "https://provider.example/mcp",
        )
        .unwrap();
        let error = client
            .rpc_call_with_context("tools/list", json!({}), None)
            .await
            .unwrap_err();
        assert!(
            error
                .safe_summary()
                .contains("verified request attribution")
        );
    }

    #[test]
    fn response_parser_accepts_json_and_sse_with_case_insensitive_type() {
        let json = decode_rpc_response(
            "Application/JSON; charset=utf-8",
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
            1,
        )
        .unwrap();
        assert_eq!(json["ok"], true);
        let sse = decode_rpc_response(
            "TEXT/EVENT-STREAM",
            b"data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"ok\":true}}\n\n",
            2,
        )
        .unwrap();
        assert_eq!(sse["ok"], true);
    }

    #[test]
    fn response_parser_rejects_malformed_oversized_and_content_type() {
        assert!(decode_rpc_response("application/json", b"not-json", 1).is_err());
        assert!(
            decode_rpc_response(
                "application/json",
                &vec![b'x'; crate::protocol::MAX_RESPONSE_BYTES + 1],
                1
            )
            .is_err()
        );
        assert!(decode_rpc_response("text/plain", b"{}", 1).is_err());
    }

    #[test]
    fn content_type_headers_are_required_and_unique() {
        let headers = HeaderMap::new();
        assert!(response_content_type(&headers).is_err());
        let mut headers = HeaderMap::new();
        headers.append(
            "content-type",
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        headers.append(
            "Content-Type",
            reqwest::header::HeaderValue::from_static("text/event-stream"),
        );
        assert!(response_content_type(&headers).is_err());
    }

    #[test]
    fn host_decision_mismatch_is_redaction_safe() {
        let context = HostEgressContext {
            connector_id: "fcp.mcp-bridge".into(),
            operation_id: "mcp.tools.list".into(),
            resource_uri: "fcp://mcp/server".into(),
            zone_id: "z:private".into(),
            request_id: "session:1".into(),
            correlation_id: None,
            capability_token_cbor_b64: "secret-token".into(),
        };
        let decision = HostEgressDecisionMetadata {
            connector_id: "wrong".into(),
            operation_id: context.operation_id.clone(),
            zone_id: context.zone_id.clone(),
            request_id: context.request_id.clone(),
            correlation_id: None,
            execution_mode: "host_egress_proxy".into(),
            constraint_source: "managed_connector_config.operation_network_constraints".into(),
            decision: "allow".into(),
            resolved_host: "provider.example".into(),
            resolved_port: 443,
            credential_injected: true,
            elapsed_ms: 1,
        };
        let error = validate_host_egress_decision(
            &decision,
            &context,
            &Url::parse("https://provider.example/mcp").unwrap(),
        )
        .unwrap_err();
        let debug = format!("{error:?}");
        assert!(!debug.contains("secret-token"));
        assert!(!debug.contains("fcp://mcp/server"));
    }

    #[test]
    fn legacy_read_headers_are_sessionful_without_modern_headers() {
        let session =
            LegacySession::new(ProtocolVersion::V20251125, Some("session-secret")).unwrap();
        let plan = session
            .headers(McpMethod::ResourcesRead, Some("resource-secret"))
            .unwrap();
        let headers = protocol_headers(&plan);
        assert!(
            headers
                .iter()
                .any(|(name, value)| { name == "MCP-Protocol-Version" && value == "2025-11-25" })
        );
        assert!(
            headers
                .iter()
                .any(|(name, value)| { name == "Mcp-Session-Id" && value == "session-secret" })
        );
        assert!(!headers.iter().any(|(name, _)| name == "Mcp-Method"));
        assert!(!headers.iter().any(|(name, _)| name == "Mcp-Name"));
    }

    #[test]
    fn legacy_initialized_headers_carry_version_and_session_only() {
        let session = LegacySession::new(ProtocolVersion::V20250618, Some("sid")).unwrap();
        let plan = session.headers(McpMethod::Initialized, None).unwrap();
        let headers = protocol_headers(&plan);
        assert!(
            headers
                .iter()
                .any(|(name, value)| { name == "MCP-Protocol-Version" && value == "2025-06-18" })
        );
        assert!(
            headers
                .iter()
                .any(|(name, value)| { name == "Mcp-Session-Id" && value == "sid" })
        );
        assert!(!headers.iter().any(|(name, _)| name == "Mcp-Method"));
        assert!(!headers.iter().any(|(name, _)| name == "Mcp-Name"));
    }

    #[test]
    fn legacy_session_header_validation_is_bounded_and_unique() {
        let duplicate = vec![
            ("mcp-session-id".into(), "one".into()),
            ("MCP-SESSION-ID".into(), "two".into()),
        ];
        assert!(single_header(&duplicate, "mcp-session-id").is_err());
        let invalid = vec![("mcp-session-id".into(), "bad\nvalue".into())];
        assert!(single_header(&invalid, "mcp-session-id").is_ok());
        assert!(LegacySession::new(ProtocolVersion::V20251125, Some("bad\nvalue")).is_err());
    }

    #[test]
    fn recognized_modern_400_is_not_a_legacy_fallback() {
        assert!(matches!(
            classify_modern_400(br#"{"error":{"code":-32020}}"#),
            Modern400Decision::Recognized { .. }
        ));
        assert_eq!(classify_modern_400(b""), Modern400Decision::LegacyFallback);
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_modern_success_is_one_stateless_post() {
        let server = MockServer::start().await;
        mount_sequence(&server, vec![rpc_response(200, 1, json!({"tools": []}))]).await;
        let client = loopback_client(&server);

        let result = client.rpc_call("tools/list", json!({})).await.unwrap();
        assert_eq!(result, json!({"tools": []}));

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(request_methods(&requests), vec!["tools/list"]);
        let body = request_json(&requests[0]);
        assert_eq!(body["id"], 1);
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        assert_eq!(
            header(&requests[0], "MCP-Protocol-Version").as_deref(),
            Some("2026-07-28")
        );
        assert_eq!(
            header(&requests[0], "Mcp-Method").as_deref(),
            Some("tools/list")
        );
        assert!(!has_header(&requests[0], "Mcp-Session-Id"));
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_modern_tools_call_has_exact_metadata_and_headers() {
        let server = MockServer::start().await;
        mount_sequence(&server, vec![rpc_response(200, 1, json!({"ok": true}))]).await;
        let client = loopback_client(&server);

        let result = client
            .tools_call_with_context("tool", &json!({"input": true}), test_context())
            .await
            .unwrap();
        assert_eq!(result, json!({"ok": true}));

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        let body = request_json(request);
        assert_eq!(body["id"], 1);
        assert_eq!(body["method"], "tools/call");
        assert_eq!(body["params"]["name"], "tool");
        assert_eq!(body["params"]["arguments"], json!({"input": true}));
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
            json!({})
        );
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"],
            json!({"name": "fcp-mcp-bridge", "version": "0.1.0"})
        );
        assert_eq!(
            header(request, "MCP-Protocol-Version").as_deref(),
            Some("2026-07-28")
        );
        assert_eq!(header(request, "Mcp-Method").as_deref(), Some("tools/call"));
        assert_eq!(header(request, "Mcp-Name").as_deref(), Some("tool"));
        assert!(!has_header(request, "Mcp-Session-Id"));
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_tools_call_sentinel_name_is_exactly_encoded() {
        let server = MockServer::start().await;
        mount_sequence(&server, vec![rpc_response(200, 1, json!({"ok": true}))]).await;
        let client = loopback_client(&server);
        let name = "=?base64?YWJj?=";

        client.tools_call(name, &json!({})).await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            header(&requests[0], "Mcp-Name").as_deref(),
            Some("=?base64?PT9iYXNlNjQ/WVdKaj89?=")
        );
        assert_eq!(request_json(&requests[0])["params"]["name"], name);
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_legacy_tools_call_uses_cached_session_once() {
        let server = MockServer::start().await;
        mount_sequence(
            &server,
            vec![
                ResponseTemplate::new(400).set_body_string("legacy server"),
                initialize_response(2, Some("session-a")),
                ResponseTemplate::new(202),
                rpc_response(200, 4, json!({"tools": []})),
                rpc_response(200, 5, json!({"ok": true})),
            ],
        )
        .await;
        let client = loopback_client(&server);

        client.tools_list().await.unwrap();
        assert_eq!(
            client.tools_call("tool", &json!({})).await.unwrap(),
            json!({"ok": true})
        );

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 5);
        assert_eq!(
            request_methods(&requests),
            vec![
                "tools/list",
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/call"
            ]
        );
        let call = &requests[4];
        let body = request_json(call);
        assert_eq!(body["id"], 5);
        assert_eq!(body["params"]["name"], "tool");
        assert!(body["params"].get("_meta").is_none());
        assert_eq!(
            header(call, "MCP-Protocol-Version").as_deref(),
            Some("2025-11-25")
        );
        assert_eq!(header(call, "Mcp-Session-Id").as_deref(), Some("session-a"));
        assert!(!has_header(call, "Mcp-Method"));
        assert!(!has_header(call, "Mcp-Name"));
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_legacy_tools_call_404_clears_cache_without_retry() {
        let server = MockServer::start().await;
        mount_sequence(
            &server,
            vec![
                ResponseTemplate::new(400).set_body_string("legacy server"),
                initialize_response(2, Some("session-a")),
                ResponseTemplate::new(202),
                rpc_response(200, 4, json!({"tools": []})),
                ResponseTemplate::new(404),
            ],
        )
        .await;
        let client = loopback_client(&server);

        client.tools_list().await.unwrap();
        let error = client.tools_call("tool", &json!({})).await.unwrap_err();
        assert!(matches!(error, McpBridgeError::NotFound { .. }));
        assert!(client.legacy_session.lock().await.is_none());
        assert_eq!(server.received_requests().await.unwrap().len(), 5);
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_tools_call_errors_are_single_attempts_without_auth_retry() {
        for status in [400, 401] {
            let server = MockServer::start().await;
            mount_sequence(&server, vec![ResponseTemplate::new(status)]).await;
            let client = loopback_client(&server);

            let _ = client.tools_call("tool", &json!({})).await;
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
            assert_eq!(client.metrics().auth_retry_count, 0);
        }

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mcp"))
            .respond_with_err(test_transport_error)
            .mount(&server)
            .await;
        let client = loopback_client(&server);
        let _ = client.tools_call("tool", &json!({})).await;
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert_eq!(client.metrics().auth_retry_count, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_cancelled_read_is_single_attempt_and_client_remains_usable() {
        let server = MockServer::start().await;
        mount_sequence(
            &server,
            vec![
                rpc_response(200, 1, json!({"tools": []})).set_delay(Duration::from_millis(250)),
                rpc_response(200, 2, json!({"tools": []})),
            ],
        )
        .await;
        let client = Arc::new(loopback_client(&server));
        let task_client = Arc::clone(&client);
        let handle = fcp_async_core::task::spawn(async move {
            task_client.rpc_call("tools/list", json!({})).await
        });

        let mut observed = false;
        for _ in 0..20 {
            if server.received_requests().await.unwrap_or_default().len() == 1 {
                observed = true;
                break;
            }
            fcp_async_core::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            observed,
            "the delayed request should be observed before abort"
        );

        handle.abort();
        let join_error = handle
            .await
            .expect_err("aborted read must return JoinError");
        assert!(join_error.is_cancelled());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert_eq!(client.metrics().auth_retry_count, 0);
        assert_eq!(client.metrics().session_expired_retry_count, 0);
        assert!(client.legacy_session.lock().await.is_none());

        let result = client.rpc_call("tools/list", json!({})).await.unwrap();
        assert_eq!(result, json!({"tools": []}));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(request_json(&requests[0])["id"], 1);
        assert_eq!(request_json(&requests[1])["id"], 2);
    }

    #[fcp_async_core::runtime::test]
    async fn tools_call_validation_is_bounded_and_requires_object_arguments() {
        let client = McpClient::new(
            McpAuth {
                api_key: None,
                credential_id: None,
            },
            "http://127.0.0.1:12345/mcp",
        )
        .unwrap();
        assert!(matches!(
            client.tools_call("", &json!({})).await,
            Err(McpBridgeError::InvalidInput(_))
        ));
        assert!(matches!(
            client
                .tools_call(
                    &"x".repeat(crate::protocol::MAX_PUBLIC_ID_BYTES + 1),
                    &json!({})
                )
                .await,
            Err(McpBridgeError::InvalidInput(_))
        ));
        assert!(matches!(
            client.tools_call("tool", &json!([])).await,
            Err(McpBridgeError::InvalidInput(_))
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_recognized_modern_400_does_not_initialize() {
        let server = MockServer::start().await;
        mount_sequence(
            &server,
            vec![ResponseTemplate::new(400).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32020}
            }))],
        )
        .await;
        let client = loopback_client(&server);

        let error = client.rpc_call("tools/list", json!({})).await.unwrap_err();
        assert!(matches!(
            error,
            McpBridgeError::Api {
                status_code: 400,
                ..
            }
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert_eq!(client.metrics().auth_retry_count, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_legacy_sequence_reuses_cached_session() {
        let server = MockServer::start().await;
        mount_sequence(
            &server,
            vec![
                ResponseTemplate::new(400).set_body_string("legacy server"),
                initialize_response(2, Some("session-a")),
                ResponseTemplate::new(202),
                rpc_response(200, 4, json!({"ok": true})),
                rpc_response(200, 5, json!({"ok": true})),
            ],
        )
        .await;
        let client = loopback_client(&server);

        client.rpc_call("tools/list", json!({})).await.unwrap();
        client.rpc_call("tools/list", json!({})).await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 5);
        assert_eq!(
            request_methods(&requests),
            vec![
                "tools/list",
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/list"
            ]
        );

        let initialize = request_json(&requests[1]);
        assert_eq!(initialize["id"], 2);
        assert!(initialize["params"].get("_meta").is_none());
        assert_eq!(
            header(&requests[1], "Content-Type").as_deref(),
            Some("application/json")
        );
        assert_eq!(
            header(&requests[1], "Accept").as_deref(),
            Some("application/json, text/event-stream")
        );
        for name in [
            "MCP-Protocol-Version",
            "Mcp-Session-Id",
            "Mcp-Method",
            "Mcp-Name",
        ] {
            assert!(!has_header(&requests[1], name), "initialize sent {name}");
        }

        for request in &requests[2..] {
            let body = request_json(request);
            assert!(body["params"].get("_meta").is_none());
            assert_eq!(
                header(request, "MCP-Protocol-Version").as_deref(),
                Some("2025-11-25")
            );
            assert_eq!(
                header(request, "Mcp-Session-Id").as_deref(),
                Some("session-a")
            );
            assert!(!has_header(request, "Mcp-Method"));
            assert!(!has_header(request, "Mcp-Name"));
        }
        assert!(request_json(&requests[2])["id"].is_null());
        assert_eq!(request_json(&requests[3])["id"], 4);
        assert_eq!(request_json(&requests[4])["id"], 5);
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_session_404_reinitializes_once_and_clears_on_second_404() {
        let server = MockServer::start().await;
        mount_sequence(
            &server,
            vec![
                ResponseTemplate::new(400).set_body_string("legacy server"),
                initialize_response(2, Some("session-a")),
                ResponseTemplate::new(202),
                rpc_response(200, 4, json!({"ok": true})),
                ResponseTemplate::new(404),
                initialize_response(6, Some("session-b")),
                ResponseTemplate::new(202),
                ResponseTemplate::new(404),
            ],
        )
        .await;
        let client = loopback_client(&server);

        client.rpc_call("tools/list", json!({})).await.unwrap();
        let error = client.rpc_call("tools/list", json!({})).await.unwrap_err();
        assert!(matches!(error, McpBridgeError::NotFound { .. }));
        assert_eq!(client.metrics().session_expired_retry_count, 1);
        assert_eq!(client.metrics().auth_retry_count, 0);
        assert!(client.legacy_session.lock().await.is_none());

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 8);
        assert_eq!(
            request_methods(&requests),
            vec![
                "tools/list",
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/list",
                "initialize",
                "notifications/initialized",
                "tools/list"
            ]
        );
        assert_eq!(request_json(&requests[4])["id"], 5);
        assert_eq!(request_json(&requests[7])["id"], 8);
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_legacy_session_without_id_does_not_retry_404() {
        let server = MockServer::start().await;
        mount_sequence(
            &server,
            vec![
                ResponseTemplate::new(400).set_body_string("legacy server"),
                initialize_response(2, None),
                ResponseTemplate::new(202),
                ResponseTemplate::new(404),
            ],
        )
        .await;
        let client = loopback_client(&server);

        let error = client.rpc_call("tools/list", json!({})).await.unwrap_err();
        assert!(matches!(error, McpBridgeError::NotFound { .. }));
        assert_eq!(client.metrics().session_expired_retry_count, 0);
        assert_eq!(server.received_requests().await.unwrap().len(), 4);
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_http_and_transport_failures_do_not_fallback_or_retry() {
        for status in [401, 403, 429] {
            let server = MockServer::start().await;
            mount_sequence(&server, vec![ResponseTemplate::new(status)]).await;
            let client = loopback_client(&server);
            let _ = client.rpc_call("tools/list", json!({})).await;
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
            assert_eq!(client.metrics().auth_retry_count, 0);
            assert_eq!(client.metrics().session_expired_retry_count, 0);
        }

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mcp"))
            .respond_with_err(test_transport_error)
            .mount(&server)
            .await;
        let client = loopback_client(&server);
        let error = client.rpc_call("tools/list", json!({})).await.unwrap_err();
        assert!(matches!(
            error,
            McpBridgeError::Api {
                status_code: 502,
                ..
            }
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert_eq!(client.metrics().auth_retry_count, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_initialized_notification_must_be_202_and_empty() {
        for notification_response in [
            ResponseTemplate::new(200),
            ResponseTemplate::new(202).set_body_string("unexpected"),
        ] {
            let server = MockServer::start().await;
            mount_sequence(
                &server,
                vec![
                    ResponseTemplate::new(400).set_body_string("legacy server"),
                    initialize_response(2, Some("session-a")),
                    notification_response,
                ],
            )
            .await;
            let client = loopback_client(&server);

            let error = client.rpc_call("tools/list", json!({})).await.unwrap_err();
            assert!(matches!(error, McpBridgeError::Api { .. }));
            assert_eq!(server.received_requests().await.unwrap().len(), 3);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn wiremock_invalid_or_duplicate_session_header_fails_closed() {
        let invalid = initialize_response(2, None).insert_header("Mcp-Session-Id", "");
        let duplicate = initialize_response(2, None)
            .append_header("Mcp-Session-Id", "session-a")
            .append_header("mcp-session-id", "session-b");
        for response in [invalid, duplicate] {
            let server = MockServer::start().await;
            mount_sequence(
                &server,
                vec![
                    ResponseTemplate::new(400).set_body_string("legacy server"),
                    response,
                ],
            )
            .await;
            let client = loopback_client(&server);

            let error = client.rpc_call("tools/list", json!({})).await.unwrap_err();
            assert!(matches!(
                error,
                McpBridgeError::Api {
                    status_code: 502,
                    ..
                }
            ));
            assert_eq!(server.received_requests().await.unwrap().len(), 2);
        }
    }
}
