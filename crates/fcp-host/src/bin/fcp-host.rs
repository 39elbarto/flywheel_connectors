//! Minimal fcp-host HTTP server with discovery and doctor endpoints.

use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::{Path as FsPath, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use asupersync_tokio_compat::hyper_bridge::AsupersyncExecutor;
use asupersync_tokio_compat::io::TokioIo;
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, VARY},
    },
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use fcp_async_core::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use fcp_async_core::net::TcpListener;
#[cfg(unix)]
use fcp_async_core::net::UnixListener;
use fcp_async_core::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use fcp_async_core::sync::{Mutex, RwLock};
use fcp_async_core::task::{self, JoinHandle};
use fcp_core::{
    ConnectorHealth, ConnectorId, HealthSnapshot, Introspection, InvokeRequest, InvokeResponse,
    LifecycleError, LifecycleManager, LifecycleRecord, LifecycleState, LifecycleStatus, RequestId,
    RolloutPolicy, SafetyTier, SelfCheckReport, SoftwareBillOfMaterials, SupplyChainAttestation,
    TransitionReason,
};
use fcp_host::{
    BatchExecutor, BatchInvokeRequest, BatchInvokeResponse, BatchOperation, BatchOperationError,
    BatchOptions, BatchStatus, BudgetPolicyEngine, CacheMetadata, CacheValidator,
    CancellationController, CancellationRequest, CancellationResponse, ConnectorArchetype,
    ConnectorInventoryResponse, ConnectorRegistry, ConnectorSummary, DiscoveryEndpoint,
    DiscoveryFilter, DiscoveryResponse, DoctorReport, DoctorRequest, DoctorService, GateOutcome,
    HostHealthResponse, HostHealthStatus, IntrospectionResponse, OperationResult,
    OperationResultStatus, PreflightRequest, PreflightResponse, RequestPriority, ResilienceError,
    ResilienceLayer, RolloutController, RolloutDecision, RolloutObservation, RolloutOutcome,
    SafetyTierExt, SupplyChainGate, SupplyChainGateConfig, merge_connector_health,
};
use fcp_host::{HostError, HostResult};
use futures_util::future::join_all;
use hyper::body::Incoming;
use hyper_util::{
    server::conn::auto::Builder as HyperConnectionBuilder, service::TowerToHyperService,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower::ServiceExt;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Deserialize)]
struct ConnectorConfig {
    id: String,
    binary: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    config: Option<serde_json::Value>,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    version: Option<String>,
}

struct SubprocessConnector {
    summary: ConnectorSummary,
    runner: Mutex<ConnectorProcessRunner>,
    resilience: Arc<ResilienceLayer>,
}

impl SubprocessConnector {
    async fn spawn(config: ConnectorConfig, resilience: Arc<ResilienceLayer>) -> HostResult<Self> {
        let connector_id: ConnectorId = config.id.parse().map_err(|err| {
            HostError::InvalidFilter(format!("invalid connector id '{}': {err}", config.id))
        })?;
        let version = if let Some(raw) = &config.version {
            semver::Version::parse(raw).map_err(|err| {
                HostError::InvalidFilter(format!(
                    "invalid version for connector '{}': {err}",
                    connector_id.as_str()
                ))
            })?
        } else {
            semver::Version::new(1, 0, 0)
        };

        let summary = ConnectorSummary {
            id: connector_id.clone(),
            name: config
                .name
                .clone()
                .unwrap_or_else(|| connector_id.to_string()),
            description: config.description.clone(),
            version,
            categories: config.categories.clone(),
            tool_count: 0,
            max_safety_tier: SafetyTier::Safe,
            enabled: true,
            health: ConnectorHealth::healthy(),
            last_health_check: None,
        };

        let runner = ConnectorProcessRunner::spawn(&config.binary, &config.args, &config.env)
            .await
            .map_err(|err| HostError::Internal(format!("spawn failed: {err}")))?;

        let connector = Self {
            summary,
            runner: Mutex::new(runner),
            resilience,
        };
        connector.resilience.ensure_connector(&connector.summary.id);

        if let Some(config_payload) = config.config {
            connector.configure(config_payload).await?;
        }

        Ok(connector)
    }

    async fn configure(&self, config: serde_json::Value) -> HostResult<()> {
        let _ = self.rpc("configure", config).await?;
        Ok(())
    }

    async fn rpc(&self, method: &str, params: serde_json::Value) -> HostResult<serde_json::Value> {
        let connector_id = self.summary.id.clone();
        self.resilience
            .execute(&connector_id, operation_priority(method), method, async {
                let mut runner = self.runner.lock().await;
                let request = json!({
                    "jsonrpc": "2.0",
                    "id": RequestId::random().0,
                    "method": method,
                    "params": params,
                });
                let response = runner.request(&request).await.map_err(|err| {
                    HostError::RegistryError(format!("connector IO error: {err}"))
                })?;
                if let Some(error) = response.get("error") {
                    return Err(HostError::RegistryError(format!(
                        "connector error: {error}"
                    )));
                }
                Ok(response.get("result").cloned().unwrap_or(json!({})))
            })
            .await
            .map_err(|error| map_resilience_error(&connector_id, method, error))
    }

    async fn introspect(&self) -> HostResult<Introspection> {
        let result = self.rpc("introspect", json!({})).await?;
        serde_json::from_value(result)
            .map_err(|err| HostError::RegistryError(format!("introspection parse error: {err}")))
    }

    async fn health(&self) -> HostResult<HealthSnapshot> {
        let result = self.rpc("health", json!({})).await?;
        serde_json::from_value(result)
            .map_err(|err| HostError::RegistryError(format!("health parse error: {err}")))
    }

    async fn self_check(&self) -> HostResult<SelfCheckReport> {
        let result = self.rpc("self_check", json!({})).await?;
        serde_json::from_value(result)
            .map_err(|err| HostError::RegistryError(format!("self_check parse error: {err}")))
    }

    async fn invoke(&self, request: InvokeRequest) -> HostResult<InvokeResponse> {
        let params = serde_json::to_value(request)
            .map_err(|err| HostError::RegistryError(format!("invoke encode error: {err}")))?;
        let result = self.rpc("invoke", params).await?;
        serde_json::from_value(result)
            .map_err(|err| HostError::RegistryError(format!("invoke parse error: {err}")))
    }

    async fn summary_snapshot(&self) -> ConnectorSummary {
        let mut summary = self.summary.clone();
        if let Ok(introspection) = self.introspect().await {
            summary.tool_count = introspection.operations.len() as u32;
            summary.max_safety_tier = introspection
                .operations
                .iter()
                .map(|operation| operation.safety_tier)
                .max_by_key(|tier| tier.level())
                .unwrap_or(SafetyTier::Safe);
        }
        match self.health().await {
            Ok(snapshot) => {
                summary.health = merge_connector_health(
                    ConnectorHealth::from(&snapshot.status),
                    self.resilience.connector_health(&self.summary.id),
                );
                summary.last_health_check = Some(chrono::Utc::now());
            }
            Err(err) => {
                summary.health = merge_connector_health(
                    ConnectorHealth::unavailable(format!("health check failed: {err}")),
                    self.resilience.connector_health(&self.summary.id),
                );
                summary.last_health_check = Some(chrono::Utc::now());
            }
        }
        summary
    }
}

#[derive(Clone)]
struct SubprocessRegistry {
    connectors: HashMap<ConnectorId, Arc<SubprocessConnector>>,
    _resilience: Arc<ResilienceLayer>,
    version: u64,
}

impl SubprocessRegistry {
    async fn from_configs(configs: Vec<ConnectorConfig>) -> HostResult<Self> {
        let resilience = Arc::new(ResilienceLayer::default());
        let mut map = HashMap::new();
        for config in configs {
            let connector = SubprocessConnector::spawn(config, Arc::clone(&resilience)).await?;
            map.insert(connector.summary.id.clone(), Arc::new(connector));
        }
        Ok(Self {
            connectors: map,
            _resilience: resilience,
            version: 1,
        })
    }

    async fn invoke(&self, request: InvokeRequest) -> HostResult<InvokeResponse> {
        let connector_id = request.connector_id.clone();
        let connector = self
            .connectors
            .get(&connector_id)
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;
        connector.invoke(request).await
    }
}

#[async_trait::async_trait]
impl ConnectorRegistry for SubprocessRegistry {
    async fn list(&self) -> Vec<ConnectorSummary> {
        let mut results = Vec::new();
        for connector in self.connectors.values() {
            results.push(connector.summary_snapshot().await);
        }
        results
    }

    async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
        let connector = self.connectors.get(id)?;
        Some(connector.summary_snapshot().await)
    }

    async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
        let connector = self.connectors.get(id)?;
        connector.introspect().await.ok()
    }

    async fn get_archetype(&self, id: &ConnectorId) -> Option<ConnectorArchetype> {
        self.connectors.get(id)?;
        Some(ConnectorArchetype::RequestResponse)
    }

    async fn get_rate_limits(&self, id: &ConnectorId) -> Option<fcp_core::RateLimitDeclarations> {
        self.connectors.get(id)?;
        Some(fcp_core::RateLimitDeclarations::default())
    }

    async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
        let connector = self.connectors.get(id)?;
        connector.self_check().await.ok()
    }

    fn version(&self) -> u64 {
        self.version
    }
}

struct HostLifecycleManager {
    records: RwLock<HashMap<ConnectorId, LifecycleRecord>>,
    pinned_versions: RwLock<HashMap<ConnectorId, semver::Version>>,
}

impl HostLifecycleManager {
    fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            pinned_versions: RwLock::new(HashMap::new()),
        }
    }

    async fn pin(&self, connector_id: &ConnectorId, version: semver::Version) {
        self.pinned_versions
            .write()
            .await
            .insert(connector_id.clone(), version);
    }

    async fn unpin(&self, connector_id: &ConnectorId) -> Option<semver::Version> {
        self.pinned_versions.write().await.remove(connector_id)
    }

    async fn pinned_version(&self, connector_id: &ConnectorId) -> Option<semver::Version> {
        self.pinned_versions.read().await.get(connector_id).cloned()
    }

    async fn pin_state(&self, connector_id: &ConnectorId) -> PinStateResponse {
        PinStateResponse::new(connector_id, self.pinned_version(connector_id).await)
    }

    async fn rollout_status(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<RolloutStatusResponse, LifecycleError> {
        let status = self.status(connector_id).await?;
        let records = self.records.read().await;
        let record = records
            .get(connector_id)
            .ok_or_else(|| LifecycleError::NotFound {
                connector_id: connector_id.clone(),
            })?;
        let pinned_version = self.pinned_versions.read().await.get(connector_id).cloned();
        Ok(RolloutStatusResponse {
            status,
            pinned: pinned_version.is_some(),
            pinned_version,
            canary_percent: record.canary_policy.canary_traffic_percent,
        })
    }
}

#[async_trait::async_trait]
impl LifecycleManager for HostLifecycleManager {
    async fn get(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<Option<LifecycleRecord>, LifecycleError> {
        Ok(self.records.read().await.get(connector_id).cloned())
    }

    async fn save(&self, record: &LifecycleRecord) -> Result<(), LifecycleError> {
        self.records
            .write()
            .await
            .insert(record.connector_id.clone(), record.clone());
        Ok(())
    }

    async fn promote(&self, connector_id: &ConnectorId) -> Result<LifecycleRecord, LifecycleError> {
        let mut records = self.records.write().await;
        let record = records
            .get_mut(connector_id)
            .ok_or_else(|| LifecycleError::NotFound {
                connector_id: connector_id.clone(),
            })?;
        let health_score = record.health.success_rate.min(100);
        record.transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score },
        )?;
        Ok(record.clone())
    }

    async fn rollback(
        &self,
        connector_id: &ConnectorId,
        reason: Option<String>,
    ) -> Result<LifecycleRecord, LifecycleError> {
        let mut records = self.records.write().await;
        let record = records
            .get_mut(connector_id)
            .ok_or_else(|| LifecycleError::NotFound {
                connector_id: connector_id.clone(),
            })?;
        if record.previous_version.is_none() {
            return Err(LifecycleError::NoRollbackTarget);
        }
        let health_score = record.health.success_rate.min(100);
        let failure_reason = reason.unwrap_or_else(|| "rollback requested".to_string());
        record.transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score,
                failure_reason,
            },
        )?;
        Ok(record.clone())
    }

    async fn status(&self, connector_id: &ConnectorId) -> Result<LifecycleStatus, LifecycleError> {
        let records = self.records.read().await;
        let record = records
            .get(connector_id)
            .ok_or_else(|| LifecycleError::NotFound {
                connector_id: connector_id.clone(),
            })?;
        Ok(LifecycleStatus::from_record(record, Utc::now(), false))
    }
}

struct ConnectorProcessRunner {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    _stderr_task: JoinHandle<()>,
}

impl ConnectorProcessRunner {
    async fn spawn(
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
    ) -> std::io::Result<Self> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for (key, value) in env {
            cmd.env(key, value);
        }

        let mut child = cmd.spawn()?;
        let stdin = child
            .stdin()
            .ok_or_else(|| std::io::Error::other("connector stdin unavailable"))?;
        let stdout = child
            .stdout()
            .ok_or_else(|| std::io::Error::other("connector stdout unavailable"))?;
        let stderr = child
            .stderr()
            .ok_or_else(|| std::io::Error::other("connector stderr unavailable"))?;

        let stderr_task = task::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let trimmed = line.trim_end();
                        if !trimmed.is_empty() {
                            tracing::warn!(connector_stderr = %trimmed, "connector log");
                        }
                    }
                }
            }
        });

        Ok(Self {
            _child: child,
            stdin,
            stdout: BufReader::new(stdout),
            _stderr_task: stderr_task,
        })
    }

    async fn send_json(&mut self, value: &serde_json::Value) -> std::io::Result<()> {
        let line = serde_json::to_string(value)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn read_json(&mut self) -> std::io::Result<serde_json::Value> {
        let mut line = String::new();
        let bytes = self.stdout.read_line(&mut line).await?;
        if bytes == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connector closed stdout",
            ));
        }
        serde_json::from_str::<serde_json::Value>(line.trim())
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    async fn request(&mut self, value: &serde_json::Value) -> std::io::Result<serde_json::Value> {
        self.send_json(value).await?;
        self.read_json().await
    }
}

impl Drop for ConnectorProcessRunner {
    fn drop(&mut self) {
        // Prevent zombie process leaks by terminating the child on drop.
        let _ = self._child.start_kill();
    }
}

async fn handle_accept_error(err: std::io::Error) {
    if matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    ) {
        return;
    }

    tracing::error!(error = %err, "accept error");
    fcp_async_core::time::sleep(Duration::from_secs(1)).await;
}

fn hyper_executor() -> AsupersyncExecutor {
    AsupersyncExecutor::with_spawn_fn(|future| {
        std::mem::drop(task::spawn(future));
    })
}

fn spawn_http_connection<IO>(io: IO, app: Router)
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let tower_service = app.map_request(|request: hyper::Request<Incoming>| request.map(Body::new));
    let hyper_service = TowerToHyperService::new(tower_service);

    std::mem::drop(task::spawn(async move {
        let mut builder = HyperConnectionBuilder::new(hyper_executor());
        builder.http2().enable_connect_protocol();

        let mut connection = pin!(builder.serve_connection_with_upgrades(io, hyper_service));
        if let Err(err) = connection.as_mut().await {
            tracing::debug!(error = %err, "failed to serve connection");
        }
    }));
}

async fn serve_tcp(listener: TcpListener, app: Router) -> HostResult<()> {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::debug!(transport = "tcp", remote_addr = %addr, "accepted connection");
                spawn_http_connection(TokioIo::new(stream), app.clone());
            }
            Err(err) => handle_accept_error(err).await,
        }
    }
}

#[cfg(unix)]
async fn serve_unix(listener: UnixListener, app: Router) -> HostResult<()> {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::debug!(transport = "unix", remote_addr = ?addr, "accepted connection");
                spawn_http_connection(TokioIo::new(stream), app.clone());
            }
            Err(err) => handle_accept_error(err).await,
        }
    }
}

#[derive(Clone)]
struct AppState {
    registry: Arc<SubprocessRegistry>,
    doctor: DoctorService<SubprocessRegistry>,
    discovery: Arc<DiscoveryEndpoint<SubprocessRegistry, BudgetPolicyEngine>>,
    cancellation: Arc<CancellationController>,
    lifecycle: Arc<HostLifecycleManager>,
    rollout: Arc<RolloutController<SubprocessRegistry, HostLifecycleManager>>,
    supply_chain: Arc<SupplyChainGate>,
    started_at: Instant,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryRequestBody {
    #[serde(default)]
    filter: Option<DiscoveryFilter>,
    #[serde(rename = "_cache", default)]
    cache: Option<CacheValidator>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpBatchInvokeRequest {
    operations: Vec<HttpBatchOperation>,
    #[serde(default)]
    options: BatchOptions,
}

impl HttpBatchInvokeRequest {
    fn planning_request(&self) -> BatchInvokeRequest {
        BatchInvokeRequest {
            operations: self
                .operations
                .iter()
                .map(|operation| BatchOperation {
                    id: operation.id.clone(),
                    tool: format!(
                        "{}#{}",
                        operation.request.connector_id, operation.request.operation
                    ),
                    input: serde_json::Value::Null,
                    depends_on: operation.depends_on.clone(),
                    zone: Some(operation.request.zone_id.to_string()),
                })
                .collect(),
            options: self.options.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpBatchOperation {
    id: String,
    request: InvokeRequest,
    #[serde(default)]
    depends_on: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DiscoverPayload {
    Request(DiscoveryRequestBody),
    Filter(Option<DiscoveryFilter>),
}

impl DiscoverPayload {
    fn into_parts(self) -> (Option<DiscoveryFilter>, Option<CacheValidator>) {
        match self {
            Self::Request(request) => (request.filter, request.cache),
            Self::Filter(filter) => (filter, None),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RolloutScheduleRequest {
    connector_id: String,
    version: semver::Version,
    #[serde(default)]
    previous_version: Option<semver::Version>,
    policy: RolloutPolicy,
    #[serde(default)]
    observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RolloutEvaluateRequest {
    connector_id: String,
    invocation_succeeded: bool,
    #[serde(default)]
    latency_ms: Option<u32>,
    #[serde(default)]
    uptime_secs: u64,
    #[serde(default)]
    pinned: bool,
    #[serde(default)]
    crashed: bool,
    policy: RolloutPolicy,
    #[serde(default)]
    observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinRequest {
    version: semver::Version,
}

#[derive(Debug, Serialize)]
struct PinStateResponse {
    connector_id: String,
    pinned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<semver::Version>,
}

impl PinStateResponse {
    fn new(connector_id: &ConnectorId, version: Option<semver::Version>) -> Self {
        Self {
            connector_id: connector_id.to_string(),
            pinned: version.is_some(),
            version,
        }
    }
}

#[derive(Debug, Serialize)]
struct RolloutStatusResponse {
    #[serde(flatten)]
    status: LifecycleStatus,
    pinned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pinned_version: Option<semver::Version>,
    canary_percent: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackRequest {
    connector_id: String,
    to_version: semver::Version,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct RollbackResponse {
    connector_id: String,
    state: LifecycleState,
    from_version: semver::Version,
    to_version: semver::Version,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupplyChainVerifyRequest {
    connector_id: String,
    version: semver::Version,
    artifact_digest: String,
    #[serde(default)]
    attestation: Option<SupplyChainAttestation>,
    #[serde(default)]
    sbom: Option<SoftwareBillOfMaterials>,
}

fn parse_http_datetime(value: &str) -> Option<DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|parsed| parsed.with_timezone(&Utc))
}

fn format_http_datetime(value: &DateTime<Utc>) -> String {
    value.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn cache_validator_from_headers(headers: &HeaderMap) -> Option<CacheValidator> {
    let if_none_match = headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let if_modified_since = headers
        .get(IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_datetime);

    if if_none_match.is_none() && if_modified_since.is_none() {
        None
    } else {
        Some(CacheValidator {
            if_none_match,
            if_modified_since,
        })
    }
}

fn merge_cache_validator(
    request_validator: Option<CacheValidator>,
    headers: &HeaderMap,
) -> Option<CacheValidator> {
    let header_validator = cache_validator_from_headers(headers);
    match (request_validator, header_validator) {
        (Some(mut request), Some(header)) => {
            if request.if_none_match.is_none() {
                request.if_none_match = header.if_none_match;
            }
            if request.if_modified_since.is_none() {
                request.if_modified_since = header.if_modified_since;
            }
            Some(request)
        }
        (Some(request), None) => Some(request),
        (None, Some(header)) => Some(header),
        (None, None) => None,
    }
}

fn cache_headers(cache: Option<&CacheMetadata>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let Some(cache) = cache else {
        return headers;
    };

    if let Ok(value) = HeaderValue::from_str(&cache.etag) {
        headers.insert(ETAG, value);
    }
    if let Ok(value) = HeaderValue::from_str(&format_http_datetime(&cache.last_modified)) {
        headers.insert(LAST_MODIFIED, value);
    }

    let mut cache_control = format!("max-age={}", cache.max_age_seconds);
    if let Some(stale_while_revalidate_seconds) = cache.stale_while_revalidate_seconds {
        cache_control.push_str(&format!(
            ", stale-while-revalidate={stale_while_revalidate_seconds}"
        ));
    }
    if let Ok(value) = HeaderValue::from_str(&cache_control) {
        headers.insert(CACHE_CONTROL, value);
    }
    headers.insert(
        VARY,
        HeaderValue::from_static("If-None-Match, If-Modified-Since"),
    );
    headers
}

#[derive(Debug)]
enum BindTarget {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

fn load_connector_configs() -> HostResult<Vec<ConnectorConfig>> {
    let payload = if let Ok(path) = std::env::var("FCP_HOST_CONNECTORS_FILE") {
        if path.trim().is_empty() {
            None
        } else {
            Some(std::fs::read_to_string(path).map_err(|err| {
                HostError::Internal(format!("failed to read FCP_HOST_CONNECTORS_FILE: {err}"))
            })?)
        }
    } else {
        std::env::var("FCP_HOST_CONNECTORS").ok()
    };

    let Some(raw) = payload else {
        return Ok(Vec::new());
    };
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    serde_json::from_str(&raw)
        .map_err(|err| HostError::InvalidFilter(format!("invalid connector config json: {err}")))
}

fn resolve_self_check_timeout() -> HostResult<Option<Duration>> {
    let raw = match std::env::var("FCP_HOST_SELF_CHECK_TIMEOUT_MS") {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    let millis: u64 = raw.parse().map_err(|err| {
        HostError::InvalidFilter(format!("invalid FCP_HOST_SELF_CHECK_TIMEOUT_MS: {err}"))
    })?;
    Ok(Some(Duration::from_millis(millis)))
}

fn resolve_supply_chain_gate_config() -> HostResult<SupplyChainGateConfig> {
    let mut config = SupplyChainGateConfig::default();

    if let Some(cache_capacity) = read_env_usize("FCP_HOST_SUPPLY_CHAIN_CACHE_CAPACITY")? {
        if cache_capacity == 0 {
            return Err(HostError::InvalidFilter(
                "FCP_HOST_SUPPLY_CHAIN_CACHE_CAPACITY must be >= 1".to_string(),
            ));
        }
        config.cache_capacity = cache_capacity;
    }

    if let Some(allow_dev_overrides) = read_env_bool("FCP_HOST_SUPPLY_CHAIN_ALLOW_DEV_OVERRIDES")? {
        config.allow_dev_overrides = allow_dev_overrides;
    }

    let policy = &mut config.policy;
    if let Some(require_attestation) = read_env_bool("FCP_HOST_SUPPLY_CHAIN_REQUIRE_ATTESTATION")? {
        policy.require_attestation = require_attestation;
    }
    if let Some(require_sbom) = read_env_bool("FCP_HOST_SUPPLY_CHAIN_REQUIRE_SBOM")? {
        policy.require_sbom = require_sbom;
    }
    if let Some(min_slsa_level) = read_env_u8("FCP_HOST_SUPPLY_CHAIN_MIN_SLSA_LEVEL")? {
        if min_slsa_level > 4 {
            return Err(HostError::InvalidFilter(
                "FCP_HOST_SUPPLY_CHAIN_MIN_SLSA_LEVEL must be between 0 and 4".to_string(),
            ));
        }
        policy.min_slsa_level = min_slsa_level;
    }
    if let Some(trusted_builders) = read_env_csv("FCP_HOST_SUPPLY_CHAIN_TRUSTED_BUILDERS") {
        policy.trusted_builders = trusted_builders;
    }
    if let Some(allow_unsigned) = read_env_bool("FCP_HOST_SUPPLY_CHAIN_ALLOW_UNSIGNED")? {
        policy.allow_unsigned = allow_unsigned;
    }
    if let Some(require_digest_match) = read_env_bool("FCP_HOST_SUPPLY_CHAIN_REQUIRE_DIGEST_MATCH")?
    {
        policy.require_digest_match = require_digest_match;
    }

    Ok(config)
}

fn read_env_bool(name: &str) -> HostResult<Option<bool>> {
    let raw = match std::env::var(name) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    parse_env_bool(name, trimmed).map(Some)
}

fn parse_env_bool(name: &str, raw: &str) -> HostResult<bool> {
    if raw.eq_ignore_ascii_case("true")
        || raw.eq_ignore_ascii_case("yes")
        || raw.eq_ignore_ascii_case("on")
        || raw == "1"
    {
        Ok(true)
    } else if raw.eq_ignore_ascii_case("false")
        || raw.eq_ignore_ascii_case("no")
        || raw.eq_ignore_ascii_case("off")
        || raw == "0"
    {
        Ok(false)
    } else {
        Err(HostError::InvalidFilter(format!(
            "invalid boolean value for {name}: {raw}"
        )))
    }
}

fn read_env_u8(name: &str) -> HostResult<Option<u8>> {
    let raw = match std::env::var(name) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed = trimmed
        .parse()
        .map_err(|err| HostError::InvalidFilter(format!("invalid {name}: {err}")))?;
    Ok(Some(parsed))
}

fn read_env_usize(name: &str) -> HostResult<Option<usize>> {
    let raw = match std::env::var(name) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed = trimmed
        .parse()
        .map_err(|err| HostError::InvalidFilter(format!("invalid {name}: {err}")))?;
    Ok(Some(parsed))
}

fn read_env_csv(name: &str) -> Option<Vec<String>> {
    std::env::var(name).ok().map(|raw| {
        raw.split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
}

fn resolve_bind_target() -> HostResult<BindTarget> {
    let raw = std::env::var("FCP_HOST_BIND").unwrap_or_else(|_| "127.0.0.1:9090".to_string());
    parse_bind_target(&raw)
}

fn parse_bind_target(raw: &str) -> HostResult<BindTarget> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(HostError::Internal(
            "FCP_HOST_BIND cannot be empty".to_string(),
        ));
    }

    #[cfg(unix)]
    {
        if let Some(path) = trimmed.strip_prefix("unix://") {
            return parse_unix_bind_target(path, raw);
        }

        if trimmed.starts_with('/') {
            return parse_unix_bind_target(trimmed, raw);
        }
    }

    #[cfg(not(unix))]
    if trimmed.starts_with("unix://") {
        return Err(HostError::Internal(format!(
            "unix sockets are not supported on this platform: {raw}"
        )));
    }

    parse_tcp_bind_target(trimmed, raw)
}

fn parse_tcp_bind_target(addr: &str, raw: &str) -> HostResult<BindTarget> {
    let target = addr.strip_prefix("tcp://").unwrap_or(addr);
    let socket_addr = target
        .parse()
        .map_err(|err| HostError::Internal(format!("invalid bind address '{raw}': {err}")))?;
    Ok(BindTarget::Tcp(socket_addr))
}

#[cfg(unix)]
fn parse_unix_bind_target(path: &str, raw: &str) -> HostResult<BindTarget> {
    if path.trim().is_empty() {
        return Err(HostError::Internal(format!(
            "unix socket path in FCP_HOST_BIND cannot be empty: {raw}"
        )));
    }
    Ok(BindTarget::Unix(PathBuf::from(path)))
}

#[cfg(unix)]
fn prepare_unix_socket_path(path: &FsPath) -> HostResult<()> {
    if path.exists() {
        return Err(HostError::Internal(format!(
            "unix socket path already exists: {}. Remove it manually before starting fcp-host",
            path.display()
        )));
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            HostError::Internal(format!(
                "failed to create unix socket parent directory '{}': {err}",
                parent.display()
            ))
        })?;
    }

    Ok(())
}

fn main() -> HostResult<()> {
    init_tracing();
    match fcp_async_core::runtime::block_on_sync(async_main()) {
        Ok(result) => result,
        Err(err) => Err(HostError::Internal(format!(
            "runtime bootstrap failed: {err}"
        ))),
    }
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,fcp_host=debug")),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_ansi(false)
                .with_current_span(false)
                .with_writer(std::io::stderr),
        )
        .init();
}

async fn async_main() -> HostResult<()> {
    let bind_target = resolve_bind_target()?;

    let configs = load_connector_configs()?;
    if configs.is_empty() {
        tracing::warn!("no connectors configured; doctor self-checks will fail");
    }

    let registry = Arc::new(SubprocessRegistry::from_configs(configs).await?);
    let doctor = match resolve_self_check_timeout()? {
        Some(timeout) => DoctorService::with_timeout(Arc::clone(&registry), timeout),
        None => DoctorService::new(Arc::clone(&registry)),
    };
    let discovery = Arc::new(DiscoveryEndpoint::new(
        Arc::clone(&registry),
        Arc::new(BudgetPolicyEngine::new()),
    ));
    let lifecycle = Arc::new(HostLifecycleManager::new());
    let rollout = Arc::new(RolloutController::new(
        Arc::clone(&registry),
        Arc::clone(&lifecycle),
    ));
    let supply_chain = Arc::new(SupplyChainGate::with_config(
        resolve_supply_chain_gate_config()?,
    ));
    let cancellation = Arc::new(CancellationController::new());
    let state = Arc::new(AppState {
        registry,
        doctor,
        discovery,
        cancellation,
        lifecycle,
        rollout,
        supply_chain,
        started_at: Instant::now(),
    });

    let app = Router::new()
        .route("/doctor", post(doctor_handler))
        .route("/rpc/discover", post(discover_handler))
        .route("/rpc/connectors/{connector_id}", get(connector_handler))
        .route("/rpc/introspect/{connector_id}", get(introspect_handler))
        .route("/rpc/invoke", post(invoke_handler))
        .route("/rpc/cancel", post(cancel_handler))
        .route("/rpc/operations/cancel", post(cancel_handler))
        .route("/rpc/batch", post(batch_invoke_handler))
        .route("/rpc/batch-invoke", post(batch_invoke_handler))
        .route("/rpc/preflight", post(preflight_handler))
        .route(
            "/rpc/supply-chain/verify",
            post(supply_chain_verify_handler),
        )
        .route("/rpc/health", get(health_handler))
        .route(
            "/rpc/rollout/pin/{connector_id}",
            get(rollout_pin_status_handler)
                .put(rollout_pin_handler)
                .delete(rollout_unpin_handler),
        )
        .route("/rpc/rollout/schedule", post(rollout_schedule_handler))
        .route("/rpc/rollout/evaluate", post(rollout_evaluate_handler))
        .route(
            "/rpc/rollout/rollback",
            post(rollout_manual_rollback_handler),
        )
        .route("/rpc/rollout/{connector_id}", get(rollout_status_handler))
        .with_state(state);

    match bind_target {
        BindTarget::Tcp(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|err| HostError::Internal(format!("tcp bind error: {err}")))?;
            tracing::info!(transport = "tcp", %addr, "fcp-host listening");
            serve_tcp(listener, app).await?;
        }
        #[cfg(unix)]
        BindTarget::Unix(path) => {
            prepare_unix_socket_path(&path)?;
            let listener = UnixListener::bind(&path)
                .await
                .map_err(|err| HostError::Internal(format!("unix bind error: {err}")))?;
            tracing::info!(
                transport = "unix",
                socket_path = %path.display(),
                "fcp-host listening"
            );
            serve_unix(listener, app).await?;
        }
    }

    Ok(())
}

async fn doctor_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DoctorRequest>,
) -> Result<Json<DoctorReport>, (StatusCode, String)> {
    let started_at = Instant::now();
    tracing::debug!(
        event = "doctor_request",
        zone_id = %request.zone_id,
        connector_count = request.connectors.len(),
        self_check = request.self_check,
        "processing doctor request"
    );
    match state.doctor.handle(request).await {
        Ok(report) => {
            tracing::debug!(
                event = "doctor_response",
                overall_status = ?report.overall_status,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "doctor request complete"
            );
            Ok(Json(report))
        }
        Err(err) => {
            tracing::warn!(
                event = "doctor_error",
                error = %err,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "doctor request failed"
            );
            Err(map_host_error(err))
        }
    }
}

async fn discover_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DiscoverPayload>,
) -> (HeaderMap, Json<DiscoveryResponse>) {
    let (filter, request_validator) = payload.into_parts();
    let cache_validator = merge_cache_validator(request_validator, &headers);
    let started_at = Instant::now();
    tracing::debug!(
        event = "discover_request",
        filter = ?filter,
        "processing discovery request"
    );
    let result = state
        .discovery
        .discover_query(filter, cache_validator)
        .await;
    let cache_hit = result.cache_hit;
    let response = result.response;
    tracing::debug!(
        event = "discover_response",
        connector_count = response.connectors.len(),
        registry_version = response.registry_version,
        cache_hit,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "discovery request complete"
    );
    let response_headers = cache_headers(response.cache.as_ref());
    (response_headers, Json(response))
}

async fn introspect_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(connector_id): Path<String>,
) -> Result<(HeaderMap, Json<IntrospectionResponse>), (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let cache_validator = cache_validator_from_headers(&headers);
    let started_at = Instant::now();
    tracing::debug!(
        event = "introspect_request",
        connector_id = %connector_id,
        "processing introspection request"
    );
    match state
        .discovery
        .introspect_with_cache(&connector_id, cache_validator)
        .await
    {
        Ok(response) => {
            tracing::debug!(
                event = "introspect_response",
                connector_id = %connector_id,
                tool_count = response.tools.len(),
                duration_ms = started_at.elapsed().as_millis() as u64,
                "introspection request complete"
            );
            let response_headers = cache_headers(response.cache.as_ref());
            Ok((response_headers, Json(response)))
        }
        Err(err) => {
            tracing::warn!(
                event = "introspect_error",
                connector_id = %connector_id,
                error = %err,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "introspection request failed"
            );
            Err(map_host_error(err))
        }
    }
}

async fn connector_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(connector_id): Path<String>,
) -> Result<(HeaderMap, Json<ConnectorInventoryResponse>), (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let cache_validator = cache_validator_from_headers(&headers);
    let started_at = Instant::now();
    tracing::debug!(
        event = "connector_request",
        connector_id = %connector_id,
        "processing connector inventory request"
    );
    match state
        .discovery
        .connector_with_cache(&connector_id, cache_validator)
        .await
    {
        Ok(response) => {
            tracing::debug!(
                event = "connector_response",
                connector_id = %connector_id,
                registry_version = response.registry_version,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "connector inventory request complete"
            );
            let response_headers = cache_headers(response.cache.as_ref());
            Ok((response_headers, Json(response)))
        }
        Err(err) => {
            tracing::warn!(
                event = "connector_error",
                connector_id = %connector_id,
                error = %err,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "connector inventory request failed"
            );
            Err(map_host_error(err))
        }
    }
}

async fn preflight_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PreflightRequest>,
) -> Json<PreflightResponse> {
    let connector_id = request.connector_id.clone();
    let operation = request.operation.clone();
    let started_at = Instant::now();
    let response = state.discovery.preflight(request).await;
    tracing::info!(
        event = "preflight_check",
        connector_id = %connector_id,
        operation = %operation,
        allowed = response.allowed,
        reason = ?response.reason,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "preflight request complete"
    );
    Json(response)
}

async fn cancel_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CancellationRequest>,
) -> Result<Json<CancellationResponse>, (StatusCode, String)> {
    let operation_id = request.operation_id.clone();
    let started_at = Instant::now();
    tracing::debug!(
        event = "cancel_request",
        operation_id = %operation_id,
        reason = %request.reason.label(),
        cleanup = ?request.cleanup,
        return_partial = request.return_partial,
        "processing cancellation request"
    );

    let response = state
        .cancellation
        .cancel(&request, Utc::now())
        .map_err(map_host_error)?;

    tracing::info!(
        event = "cancel_response",
        operation_id = %operation_id,
        outcome = ?response.outcome,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "cancellation request complete"
    );
    Ok(Json(response))
}

async fn invoke_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<InvokeRequest>,
) -> Result<Json<InvokeResponse>, (StatusCode, String)> {
    request.validate_idempotency_key().map_err(|err| {
        map_host_error(HostError::InvalidFilter(format!(
            "invalid invoke request: {err}"
        )))
    })?;

    let connector_id = request.connector_id.clone();
    let operation = request.operation.clone();
    let zone_id = request.zone_id.clone();
    let input = request.input.clone();
    let correlation_id = request
        .correlation_id
        .as_ref()
        .map(std::string::ToString::to_string);
    let operation_id = request.id.to_string();
    let started_at = Instant::now();

    tracing::debug!(
        event = "invoke_request",
        connector_id = %connector_id,
        operation = %operation,
        operation_id = %operation_id,
        correlation_id,
        "processing invoke request"
    );

    let preflight = state
        .discovery
        .preflight(PreflightRequest {
            connector_id: connector_id.clone(),
            operation: operation.to_string(),
            params: Some(input),
            principal: None,
            zone_id: Some(zone_id),
        })
        .await;
    if !preflight.allowed {
        let reason = preflight
            .reason
            .unwrap_or_else(|| "preflight denied invoke request".to_string());
        tracing::warn!(
            event = "invoke_error",
            connector_id = %connector_id,
            operation = %operation,
            operation_id = %operation_id,
            correlation_id,
            reason = %reason,
            duration_ms = started_at.elapsed().as_millis() as u64,
            "invoke request failed preflight"
        );
        return Err(map_host_error(HostError::PreflightFailed(reason)));
    }

    state.cancellation.track(&operation_id);
    let invoke_result = state.registry.invoke(request).await;
    state.cancellation.complete(&operation_id);

    match invoke_result {
        Ok(response) => {
            tracing::info!(
                event = "invoke_response",
                connector_id = %connector_id,
                operation = %operation,
                operation_id = %operation_id,
                correlation_id,
                status = ?response.status,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "invoke request complete"
            );
            Ok(Json(response))
        }
        Err(err) => {
            tracing::warn!(
                event = "invoke_error",
                connector_id = %connector_id,
                operation = %operation,
                operation_id = %operation_id,
                correlation_id,
                error = %err,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "invoke request failed"
            );
            Err(map_host_error(err))
        }
    }
}

fn batch_timeout_error() -> BatchOperationError {
    BatchOperationError {
        code: "BATCH_TIMEOUT".to_string(),
        message: "batch timeout exceeded".to_string(),
        retry_after_ms: None,
    }
}

fn dependency_failed_error() -> BatchOperationError {
    BatchOperationError {
        code: "DEP_FAILED".to_string(),
        message: "dependency failed".to_string(),
        retry_after_ms: None,
    }
}

fn batch_error_from_host_error(err: HostError) -> BatchOperationError {
    let code = match err {
        HostError::ConnectorNotFound(_) => "CONNECTOR_NOT_FOUND",
        HostError::InvalidFilter(_) => "INVALID_REQUEST",
        HostError::RegistryError(_) => "CONNECTOR_ERROR",
        HostError::PreflightFailed(_) => "PREFLIGHT_DENIED",
        HostError::CacheError(_) => "CACHE_ERROR",
        HostError::Unavailable(_) => "UNAVAILABLE",
        HostError::Internal(_) => "INTERNAL_ERROR",
    };

    BatchOperationError {
        code: code.to_string(),
        message: err.to_string(),
        retry_after_ms: None,
    }
}

fn skipped_batch_result(id: String, error: Option<BatchOperationError>) -> OperationResult {
    OperationResult {
        id,
        status: OperationResultStatus::Skipped,
        output: None,
        error,
        duration_ms: 0,
    }
}

fn elapsed_millis(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn dependency_failed_in_batch(
    operation: &HttpBatchOperation,
    results_map: &HashMap<String, OperationResult>,
) -> bool {
    operation.depends_on.iter().any(|dependency_id| {
        results_map
            .get(dependency_id.as_str())
            .is_some_and(|result| result.status != OperationResultStatus::Success)
    })
}

fn batch_status(aborted: bool, completed: usize, failed: usize) -> BatchStatus {
    if aborted && failed > 0 {
        BatchStatus::Aborted
    } else if failed == 0 {
        BatchStatus::Success
    } else if completed == 0 {
        BatchStatus::AllFailed
    } else {
        BatchStatus::PartialSuccess
    }
}

fn build_batch_response(
    request: &HttpBatchInvokeRequest,
    mut results_map: HashMap<String, OperationResult>,
    aborted: bool,
    started_at: Instant,
) -> BatchInvokeResponse {
    let results: Vec<OperationResult> = request
        .operations
        .iter()
        .map(|operation| {
            results_map
                .remove(operation.id.as_str())
                .unwrap_or_else(|| skipped_batch_result(operation.id.clone(), None))
        })
        .collect();

    let completed = results
        .iter()
        .filter(|result| result.status == OperationResultStatus::Success)
        .count();
    let failed = results
        .iter()
        .filter(|result| result.status == OperationResultStatus::Error)
        .count();
    let skipped = results
        .iter()
        .filter(|result| result.status == OperationResultStatus::Skipped)
        .count();

    BatchInvokeResponse {
        status: batch_status(aborted, completed, failed),
        completed,
        failed,
        skipped,
        results,
        total_duration_ms: elapsed_millis(started_at),
    }
}

async fn execute_batch_operation(
    state: Arc<AppState>,
    operation: HttpBatchOperation,
) -> OperationResult {
    let started_at = Instant::now();
    let request = operation.request;

    if let Err(err) = request.validate_idempotency_key() {
        return OperationResult {
            id: operation.id,
            status: OperationResultStatus::Error,
            output: None,
            error: Some(batch_error_from_host_error(HostError::InvalidFilter(
                format!("invalid invoke request: {err}"),
            ))),
            duration_ms: elapsed_millis(started_at),
        };
    }

    let preflight = state
        .discovery
        .preflight(PreflightRequest {
            connector_id: request.connector_id.clone(),
            operation: request.operation.to_string(),
            params: Some(request.input.clone()),
            principal: None,
            zone_id: Some(request.zone_id.clone()),
        })
        .await;

    if !preflight.allowed {
        let reason = preflight
            .reason
            .unwrap_or_else(|| "preflight denied batch operation".to_string());
        return OperationResult {
            id: operation.id,
            status: OperationResultStatus::Error,
            output: None,
            error: Some(batch_error_from_host_error(HostError::PreflightFailed(
                reason,
            ))),
            duration_ms: elapsed_millis(started_at),
        };
    }

    match state.registry.invoke(request).await {
        Ok(response) => OperationResult {
            id: operation.id,
            status: OperationResultStatus::Success,
            output: Some(
                serde_json::to_value(&response)
                    .unwrap_or_else(|_| json!({ "status": "serialization_error" })),
            ),
            error: None,
            duration_ms: elapsed_millis(started_at),
        },
        Err(err) => OperationResult {
            id: operation.id,
            status: OperationResultStatus::Error,
            output: None,
            error: Some(batch_error_from_host_error(err)),
            duration_ms: elapsed_millis(started_at),
        },
    }
}

async fn batch_invoke_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<HttpBatchInvokeRequest>,
) -> Result<Json<BatchInvokeResponse>, (StatusCode, String)> {
    let started_at = Instant::now();
    tracing::debug!(
        event = "batch_invoke_request",
        operation_count = request.operations.len(),
        max_parallelism = request.options.max_parallelism,
        stop_on_first_error = request.options.stop_on_first_error,
        timeout_ms = request.options.timeout_ms,
        "processing batch invoke request"
    );

    let executor = BatchExecutor::new();
    let planning_request = request.planning_request();
    let plan = executor.plan(&planning_request).map_err(map_host_error)?;
    let timeout = Duration::from_millis(request.options.timeout_ms);
    let max_parallelism = usize::try_from(request.options.max_parallelism)
        .unwrap_or(usize::MAX)
        .max(1);

    let operation_map: HashMap<String, HttpBatchOperation> = request
        .operations
        .iter()
        .cloned()
        .map(|operation| (operation.id.clone(), operation))
        .collect();
    let mut results_map: HashMap<String, OperationResult> = HashMap::new();
    let mut aborted = false;

    for tier in &plan.tiers {
        if aborted {
            for operation_id in &tier.operation_ids {
                results_map.insert(
                    operation_id.clone(),
                    skipped_batch_result(operation_id.clone(), None),
                );
            }
            continue;
        }

        for chunk in tier.operation_ids.chunks(max_parallelism) {
            if started_at.elapsed() >= timeout {
                aborted = true;
                let timeout_error = batch_timeout_error();
                for operation_id in chunk {
                    results_map.insert(
                        operation_id.clone(),
                        skipped_batch_result(operation_id.clone(), Some(timeout_error.clone())),
                    );
                }
                continue;
            }

            let mut ready = Vec::new();
            for operation_id in chunk {
                let operation = operation_map
                    .get(operation_id.as_str())
                    .expect("planned batch operation must exist");
                if dependency_failed_in_batch(operation, &results_map) {
                    results_map.insert(
                        operation_id.clone(),
                        skipped_batch_result(operation_id.clone(), Some(dependency_failed_error())),
                    );
                } else {
                    ready.push(operation.clone());
                }
            }

            if ready.is_empty() {
                continue;
            }

            let chunk_results = join_all(
                ready
                    .into_iter()
                    .map(|operation| execute_batch_operation(Arc::clone(&state), operation)),
            )
            .await;

            let chunk_failed = chunk_results
                .iter()
                .any(|result| result.status == OperationResultStatus::Error);
            for result in chunk_results {
                results_map.insert(result.id.clone(), result);
            }
            if request.options.stop_on_first_error && chunk_failed {
                aborted = true;
            }
        }
    }

    let response = build_batch_response(&request, results_map, aborted, started_at);
    tracing::info!(
        event = "batch_invoke_response",
        operation_count = request.operations.len(),
        completed = response.completed,
        failed = response.failed,
        skipped = response.skipped,
        status = ?response.status,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "batch invoke request complete"
    );
    Ok(Json(response))
}

async fn supply_chain_verify_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SupplyChainVerifyRequest>,
) -> Result<Json<GateOutcome>, (StatusCode, String)> {
    let SupplyChainVerifyRequest {
        connector_id,
        version,
        artifact_digest,
        attestation,
        sbom,
    } = request;
    let connector_id = parse_connector_id(&connector_id)?;
    let version = version.to_string();
    let attestation_present = attestation.is_some();
    let sbom_present = sbom.is_some();
    let started_at = Instant::now();

    tracing::debug!(
        event = "supply_chain_verify_request",
        connector_id = %connector_id,
        version = %version,
        artifact_digest = %artifact_digest,
        attestation_present,
        sbom_present,
        "processing supply-chain verification request"
    );

    match state.supply_chain.verify(
        &connector_id,
        &version,
        &artifact_digest,
        attestation.as_ref(),
        sbom.as_ref(),
    ) {
        Ok(outcome) => {
            tracing::info!(
                event = "supply_chain_verify_response",
                connector_id = %connector_id,
                version = %version,
                allowed = outcome.allowed,
                cached = outcome.cached,
                reason_code = %outcome.audit_event.reason_code,
                evidence_digest = %outcome.audit_event.evidence_digest,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "supply-chain verification request complete"
            );
            Ok(Json(outcome))
        }
        Err(err) => {
            tracing::warn!(
                event = "supply_chain_verify_error",
                connector_id = %connector_id,
                version = %version,
                error = %err,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "supply-chain verification request failed"
            );
            Err(map_host_error(err))
        }
    }
}

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<HostHealthResponse> {
    let started_at = Instant::now();
    let summaries = state.registry.list().await;
    let mut connectors = HashMap::with_capacity(summaries.len());
    let mut status = HostHealthStatus::Healthy;

    for summary in summaries {
        let connector_id = summary.id;
        let connector_health = summary.health;
        match &connector_health {
            ConnectorHealth::Healthy => {}
            ConnectorHealth::Degraded { .. } => {
                if !matches!(status, HostHealthStatus::Unhealthy) {
                    status = HostHealthStatus::Degraded;
                }
            }
            ConnectorHealth::Unavailable { .. } => {
                status = HostHealthStatus::Unhealthy;
            }
        }
        connectors.insert(connector_id, connector_health);
    }

    let response = HostHealthResponse {
        status,
        connectors,
        uptime_seconds: state.started_at.elapsed().as_secs(),
        active_connections: 0,
        timestamp: chrono::Utc::now(),
    };
    tracing::debug!(
        event = "health_response",
        status = ?response.status,
        connector_count = response.connectors.len(),
        duration_ms = started_at.elapsed().as_millis() as u64,
        "health request complete"
    );
    Json(response)
}

async fn ensure_registered_connector(
    state: &AppState,
    connector_id: &ConnectorId,
) -> Result<(), (StatusCode, String)> {
    if state.registry.get(connector_id).await.is_some() {
        Ok(())
    } else {
        Err(map_host_error(HostError::ConnectorNotFound(
            connector_id.to_string(),
        )))
    }
}

async fn rollout_pin_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    Json(request): Json<PinRequest>,
) -> Result<Json<PinStateResponse>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    ensure_registered_connector(&state, &connector_id).await?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "rollout_pin_request",
        connector_id = %connector_id,
        version = %request.version,
        "processing rollout pin request"
    );
    state
        .lifecycle
        .pin(&connector_id, request.version.clone())
        .await;
    let response = state.lifecycle.pin_state(&connector_id).await;
    tracing::info!(
        event = "rollout_pin_response",
        connector_id = %connector_id,
        pinned = response.pinned,
        version = ?response.version,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "rollout pin request complete"
    );
    Ok(Json(response))
}

async fn rollout_pin_status_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
) -> Result<Json<PinStateResponse>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    ensure_registered_connector(&state, &connector_id).await?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "rollout_pin_status_request",
        connector_id = %connector_id,
        "processing rollout pin status request"
    );
    let response = state.lifecycle.pin_state(&connector_id).await;
    tracing::debug!(
        event = "rollout_pin_status_response",
        connector_id = %connector_id,
        pinned = response.pinned,
        version = ?response.version,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "rollout pin status request complete"
    );
    Ok(Json(response))
}

async fn rollout_unpin_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
) -> Result<Json<PinStateResponse>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    ensure_registered_connector(&state, &connector_id).await?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "rollout_unpin_request",
        connector_id = %connector_id,
        "processing rollout unpin request"
    );
    let removed_version = state.lifecycle.unpin(&connector_id).await;
    let response = state.lifecycle.pin_state(&connector_id).await;
    tracing::info!(
        event = "rollout_unpin_response",
        connector_id = %connector_id,
        removed_version = ?removed_version,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "rollout unpin request complete"
    );
    Ok(Json(response))
}

async fn rollout_schedule_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RolloutScheduleRequest>,
) -> Result<Json<RolloutOutcome>, (StatusCode, String)> {
    let RolloutScheduleRequest {
        connector_id,
        version,
        previous_version,
        policy,
        observed_at,
    } = request;
    let connector_id = parse_connector_id(&connector_id)?;
    let observed_at = observed_at.unwrap_or_else(Utc::now);
    let started_at = Instant::now();
    tracing::debug!(
        event = "rollout_schedule_request",
        connector_id = %connector_id,
        version = %version,
        previous_version = ?previous_version,
        "processing rollout schedule request"
    );
    match state
        .rollout
        .schedule_canary(
            &connector_id,
            version,
            previous_version,
            &policy,
            observed_at,
        )
        .await
    {
        Ok(outcome) => {
            tracing::info!(
                event = "rollout_schedule_response",
                connector_id = %connector_id,
                state = %outcome.record.state,
                decision = ?outcome.decision,
                reason_code = %outcome.audit_event.reason_code,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "rollout schedule request complete"
            );
            Ok(Json(outcome))
        }
        Err(err) => {
            tracing::warn!(
                event = "rollout_schedule_error",
                connector_id = %connector_id,
                error = %err,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "rollout schedule request failed"
            );
            Err(map_host_error(err))
        }
    }
}

async fn rollout_evaluate_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RolloutEvaluateRequest>,
) -> Result<Json<RolloutOutcome>, (StatusCode, String)> {
    let RolloutEvaluateRequest {
        connector_id,
        invocation_succeeded,
        latency_ms,
        uptime_secs,
        pinned,
        crashed,
        policy,
        observed_at,
    } = request;
    let connector_id = parse_connector_id(&connector_id)?;
    let observed_at = observed_at.unwrap_or_else(Utc::now);
    let started_at = Instant::now();
    let effective_pinned = pinned;
    tracing::debug!(
        event = "rollout_evaluate_request",
        connector_id = %connector_id,
        invocation_succeeded,
        uptime_secs,
        pinned = effective_pinned,
        crashed,
        "processing rollout evaluate request"
    );
    let mut observation = RolloutObservation::new(invocation_succeeded, policy)
        .with_uptime_secs(uptime_secs)
        .pinned(effective_pinned)
        .crashed(crashed)
        .observed_at(observed_at);
    if let Some(latency_ms) = latency_ms {
        observation = observation.with_latency_ms(latency_ms);
    }
    match state.rollout.evaluate(&connector_id, observation).await {
        Ok(outcome) => {
            if matches!(outcome.decision, RolloutDecision::Rollback)
                && let Some(target_version) = outcome.record.previous_version.clone()
            {
                state.lifecycle.pin(&connector_id, target_version).await;
            }
            tracing::info!(
                event = "rollout_evaluate_response",
                connector_id = %connector_id,
                state = %outcome.record.state,
                decision = ?outcome.decision,
                reason_code = %outcome.audit_event.reason_code,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "rollout evaluate request complete"
            );
            Ok(Json(outcome))
        }
        Err(err) => {
            tracing::warn!(
                event = "rollout_evaluate_error",
                connector_id = %connector_id,
                error = %err,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "rollout evaluate request failed"
            );
            Err(map_host_error(err))
        }
    }
}

async fn rollout_manual_rollback_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RollbackRequest>,
) -> Result<Json<RollbackResponse>, (StatusCode, String)> {
    let RollbackRequest {
        connector_id,
        to_version,
        reason,
    } = request;
    let connector_id = parse_connector_id(&connector_id)?;
    ensure_registered_connector(&state, &connector_id).await?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "rollout_manual_rollback_request",
        connector_id = %connector_id,
        to_version = %to_version,
        "processing rollout manual rollback request"
    );

    let current = state
        .lifecycle
        .get(&connector_id)
        .await
        .map_err(|e| map_host_error(map_lifecycle_host_error(e)))?
        .ok_or_else(|| {
            map_host_error(HostError::Unavailable(format!(
                "connector '{connector_id}' has no rollout state to roll back"
            )))
        })?;
    let from_version = current.version.clone();
    let rollback_target = current.previous_version.clone().ok_or_else(|| {
        map_host_error(map_lifecycle_host_error(LifecycleError::NoRollbackTarget))
    })?;
    if to_version != rollback_target {
        return Err(map_host_error(HostError::InvalidFilter(format!(
            "requested rollback target '{to_version}' does not match current rollback target '{rollback_target}'"
        ))));
    }

    let rolled_back = state
        .lifecycle
        .rollback(&connector_id, reason)
        .await
        .map_err(|e| map_host_error(map_lifecycle_host_error(e)))?;
    state.lifecycle.pin(&connector_id, to_version.clone()).await;

    let response = RollbackResponse {
        connector_id: connector_id.to_string(),
        state: rolled_back.state,
        from_version,
        to_version: to_version.clone(),
        message: format!("connector rolled back to v{to_version} and pinned"),
    };
    tracing::info!(
        event = "rollout_manual_rollback_response",
        connector_id = %connector_id,
        from_version = %response.from_version,
        to_version = %response.to_version,
        state = %response.state,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "rollout manual rollback request complete"
    );
    Ok(Json(response))
}

async fn rollout_status_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
) -> Result<Json<RolloutStatusResponse>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "rollout_status_request",
        connector_id = %connector_id,
        "processing rollout status request"
    );
    match state.lifecycle.rollout_status(&connector_id).await {
        Ok(status) => {
            tracing::debug!(
                event = "rollout_status_response",
                connector_id = %connector_id,
                state = %status.status.state,
                pinned = status.pinned,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "rollout status request complete"
            );
            Ok(Json(status))
        }
        Err(err) => {
            let host_error = map_lifecycle_host_error(err);
            tracing::warn!(
                event = "rollout_status_error",
                connector_id = %connector_id,
                error = %host_error,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "rollout status request failed"
            );
            Err(map_host_error(host_error))
        }
    }
}

fn parse_connector_id(raw: &str) -> Result<ConnectorId, (StatusCode, String)> {
    raw.parse().map_err(|err| {
        map_host_error(HostError::InvalidFilter(format!(
            "invalid connector id '{raw}': {err}"
        )))
    })
}

fn operation_priority(method: &str) -> RequestPriority {
    match method {
        "configure" => RequestPriority::Critical,
        "health" | "self_check" => RequestPriority::High,
        "introspect" => RequestPriority::Normal,
        _ => RequestPriority::Normal,
    }
}

fn map_resilience_error(
    connector_id: &ConnectorId,
    method: &str,
    error: ResilienceError<HostError>,
) -> HostError {
    match error {
        ResilienceError::Inner(error) => error,
        ResilienceError::LoadShed { load_per_mille } => HostError::Unavailable(format!(
            "connector '{connector_id}' method '{method}' load shed at {load_per_mille}‰"
        )),
        ResilienceError::Unhealthy { reason } => HostError::Unavailable(format!(
            "connector '{connector_id}' method '{method}' unhealthy: {reason}"
        )),
        ResilienceError::CircuitOpen { retry_after } => HostError::Unavailable(format!(
            "connector '{connector_id}' method '{method}' circuit open for another {}ms",
            retry_after.as_millis()
        )),
        ResilienceError::HalfOpenLimited => HostError::Unavailable(format!(
            "connector '{connector_id}' method '{method}' half-open probe already in flight"
        )),
        ResilienceError::BulkheadFull => HostError::Unavailable(format!(
            "connector '{connector_id}' method '{method}' bulkhead queue full"
        )),
        ResilienceError::QueueTimeout { timeout } => HostError::Unavailable(format!(
            "connector '{connector_id}' method '{method}' bulkhead queue timed out after {}ms",
            timeout.as_millis()
        )),
        ResilienceError::TimedOut { timeout } => HostError::Unavailable(format!(
            "connector '{connector_id}' method '{method}' timed out after {}ms",
            timeout.as_millis()
        )),
    }
}

fn map_lifecycle_host_error(error: LifecycleError) -> HostError {
    match error {
        LifecycleError::NotFound { connector_id } => {
            HostError::ConnectorNotFound(connector_id.to_string())
        }
        other => HostError::Internal(format!("lifecycle error: {other}")),
    }
}

fn map_host_error(err: HostError) -> (StatusCode, String) {
    match err {
        HostError::ConnectorNotFound(_) => (StatusCode::NOT_FOUND, err.to_string()),
        HostError::InvalidFilter(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        HostError::PreflightFailed(_) => (StatusCode::FORBIDDEN, err.to_string()),
        HostError::CacheError(_) | HostError::Unavailable(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, err.to_string())
        }
        HostError::RegistryError(_) | HostError::Internal(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use fcp_core::OperationId;

    fn compiled_test_connector_binary() -> std::path::PathBuf {
        if let Some(path) = option_env!("CARGO_BIN_EXE_fcp-test-connector") {
            return std::path::PathBuf::from(path);
        }

        let current_exe = std::env::current_exe().expect("current test executable path");
        let deps_dir = current_exe
            .parent()
            .expect("test executable should have parent directory");
        let profile_dir = deps_dir
            .parent()
            .expect("test executable should live under target/<profile>/deps");
        let candidate = profile_dir.join(format!(
            "fcp-test-connector{}",
            std::env::consts::EXE_SUFFIX
        ));
        assert!(
            candidate.exists(),
            "expected compiled fcp-test-connector at {}",
            candidate.display()
        );
        candidate
    }

    fn subprocess_test_connector_config(connector_id: &str) -> ConnectorConfig {
        ConnectorConfig {
            id: connector_id.to_string(),
            binary: compiled_test_connector_binary().display().to_string(),
            name: Some("Test Connector".to_string()),
            description: Some("Subprocess test connector".to_string()),
            args: Vec::new(),
            env: HashMap::from([(
                "FCP_TEST_CONNECTOR_ID".to_string(),
                connector_id.to_string(),
            )]),
            config: Some(json!({})),
            categories: vec!["test".to_string()],
            version: None,
        }
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn connector_process_runner_handles_multiple_roundtrips_with_test_connector() {
        let binary = compiled_test_connector_binary();
        let mut runner = ConnectorProcessRunner::spawn(
            &binary.display().to_string(),
            &[],
            &HashMap::from([(
                "FCP_TEST_CONNECTOR_ID".to_string(),
                "fcp.test.runner:utility:1.0.0".to_string(),
            )]),
        )
        .await
        .expect("spawn test connector");

        let configure = json!({
            "jsonrpc": "2.0",
            "id": RequestId::random().0,
            "method": "configure",
            "params": {},
        });
        let configured =
            fcp_async_core::time::timeout(Duration::from_secs(2), runner.request(&configure))
                .await
                .expect("configure should not hang")
                .expect("configure should succeed");
        assert_eq!(configured["result"]["status"], "ok");

        let health = json!({
            "jsonrpc": "2.0",
            "id": RequestId::random().0,
            "method": "health",
            "params": {},
        });
        let health_response =
            fcp_async_core::time::timeout(Duration::from_secs(2), runner.request(&health))
                .await
                .expect("health should not hang")
                .expect("health should succeed");
        assert_eq!(health_response["result"]["status"]["state"], "ready");
        assert!(health_response["result"]["status"]["error"].is_null());
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_connector_supports_multiple_rpc_calls_after_configure() {
        let connector_id = "fcp.test.subprocess:utility:1.0.0";
        let connector = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            SubprocessConnector::spawn(
                subprocess_test_connector_config(connector_id),
                Arc::new(ResilienceLayer::default()),
            ),
        )
        .await
        .expect("spawn should not hang")
        .expect("spawn should succeed");

        let health = fcp_async_core::time::timeout(Duration::from_secs(2), connector.health())
            .await
            .expect("health should not hang")
            .expect("health should succeed");
        assert!(matches!(health.status, fcp_core::HealthState::Ready));

        let introspection =
            fcp_async_core::time::timeout(Duration::from_secs(2), connector.introspect())
                .await
                .expect("introspect should not hang")
                .expect("introspect should succeed");
        assert_eq!(introspection.operations.len(), 1);
        assert_eq!(
            introspection.operations[0].id,
            OperationId::from_static("test.echo")
        );
    }

    #[test]
    fn subprocess_connector_supports_multiple_rpc_calls_on_block_on_sync_runtime() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let connector_id = "fcp.test.block-on-sync:utility:1.0.0";
            let connector = fcp_async_core::time::timeout(
                Duration::from_secs(2),
                SubprocessConnector::spawn(
                    subprocess_test_connector_config(connector_id),
                    Arc::new(ResilienceLayer::default()),
                ),
            )
            .await
            .expect("spawn should not hang")
            .expect("spawn should succeed");

            let health = fcp_async_core::time::timeout(Duration::from_secs(2), connector.health())
                .await
                .expect("health should not hang")
                .expect("health should succeed");
            assert!(matches!(health.status, fcp_core::HealthState::Ready));

            let introspection =
                fcp_async_core::time::timeout(Duration::from_secs(2), connector.introspect())
                    .await
                    .expect("introspect should not hang")
                    .expect("introspect should succeed");
            assert_eq!(introspection.operations.len(), 1);
            assert_eq!(
                introspection.operations[0].id,
                OperationId::from_static("test.echo")
            );
        });

        result.expect("block_on_sync runtime should complete");
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_registry_lists_and_introspects_real_connector_configs() {
        let connector_id = ConnectorId::from_static("fcp.test.registry:utility:1.0.0");
        let registry = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            SubprocessRegistry::from_configs(vec![subprocess_test_connector_config(
                connector_id.as_str(),
            )]),
        )
        .await
        .expect("registry construction should not hang")
        .expect("registry construction should succeed");

        let summaries = fcp_async_core::time::timeout(Duration::from_secs(2), registry.list())
            .await
            .expect("registry list should not hang");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].id, connector_id);

        let introspection = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            registry.get_introspection(&connector_id),
        )
        .await
        .expect("registry introspection should not hang");
        assert!(introspection.is_some());
    }

    // ── parse_bind_target: TCP ──

    #[test]
    fn parse_bind_target_accepts_bare_tcp_socket_addr() {
        match parse_bind_target("127.0.0.1:9090").expect("tcp bind target should parse") {
            BindTarget::Tcp(addr) => assert_eq!(addr.to_string(), "127.0.0.1:9090"),
            #[cfg(unix)]
            BindTarget::Unix(path) => panic!("expected tcp bind target, got {}", path.display()),
        }
    }

    #[test]
    fn parse_bind_target_accepts_tcp_uri() {
        match parse_bind_target("tcp://127.0.0.1:9090").expect("tcp uri should parse") {
            BindTarget::Tcp(addr) => assert_eq!(addr.to_string(), "127.0.0.1:9090"),
            #[cfg(unix)]
            BindTarget::Unix(path) => panic!("expected tcp bind target, got {}", path.display()),
        }
    }

    #[test]
    fn parse_bind_target_accepts_ipv6() {
        match parse_bind_target("[::1]:8080").expect("ipv6 should parse") {
            BindTarget::Tcp(addr) => assert_eq!(addr.to_string(), "[::1]:8080"),
            #[cfg(unix)]
            BindTarget::Unix(_) => panic!("expected tcp"),
        }
    }

    #[test]
    fn parse_bind_target_accepts_ipv6_with_tcp_prefix() {
        match parse_bind_target("tcp://[::1]:8080").expect("tcp+ipv6 should parse") {
            BindTarget::Tcp(addr) => assert_eq!(addr.to_string(), "[::1]:8080"),
            #[cfg(unix)]
            BindTarget::Unix(_) => panic!("expected tcp"),
        }
    }

    #[test]
    fn parse_bind_target_accepts_zero_addr() {
        match parse_bind_target("0.0.0.0:0").expect("zero addr should parse") {
            BindTarget::Tcp(addr) => {
                assert_eq!(addr.ip().to_string(), "0.0.0.0");
                assert_eq!(addr.port(), 0);
            }
            #[cfg(unix)]
            BindTarget::Unix(_) => panic!("expected tcp"),
        }
    }

    #[test]
    fn parse_bind_target_accepts_high_port() {
        match parse_bind_target("127.0.0.1:65535").expect("high port should parse") {
            BindTarget::Tcp(addr) => assert_eq!(addr.port(), 65535),
            #[cfg(unix)]
            BindTarget::Unix(_) => panic!("expected tcp"),
        }
    }

    #[test]
    fn parse_bind_target_rejects_empty() {
        assert!(parse_bind_target("").is_err());
    }

    #[test]
    fn parse_bind_target_rejects_whitespace_only() {
        assert!(parse_bind_target("   ").is_err());
    }

    #[test]
    fn parse_bind_target_rejects_invalid_addr() {
        assert!(parse_bind_target("not-an-address").is_err());
    }

    #[test]
    fn parse_bind_target_rejects_missing_port() {
        assert!(parse_bind_target("127.0.0.1").is_err());
    }

    #[test]
    fn parse_bind_target_trims_whitespace() {
        match parse_bind_target("  127.0.0.1:9090  ").expect("trimmed should parse") {
            BindTarget::Tcp(addr) => assert_eq!(addr.to_string(), "127.0.0.1:9090"),
            #[cfg(unix)]
            BindTarget::Unix(_) => panic!("expected tcp"),
        }
    }

    // ── parse_bind_target: Unix ──

    #[cfg(unix)]
    #[test]
    fn parse_bind_target_accepts_unix_uri() {
        match parse_bind_target("unix:///tmp/fcp-host.sock").expect("unix uri should parse") {
            BindTarget::Unix(path) => {
                assert_eq!(path, std::path::PathBuf::from("/tmp/fcp-host.sock"))
            }
            BindTarget::Tcp(addr) => panic!("expected unix bind target, got {addr}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn parse_bind_target_accepts_absolute_path() {
        match parse_bind_target("/run/fcp/host.sock").expect("abs path should parse") {
            BindTarget::Unix(path) => {
                assert_eq!(path, std::path::PathBuf::from("/run/fcp/host.sock"))
            }
            BindTarget::Tcp(addr) => panic!("expected unix, got tcp {addr}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn parse_bind_target_rejects_empty_unix_path() {
        assert!(parse_bind_target("unix://").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn parse_bind_target_rejects_whitespace_unix_path() {
        assert!(parse_bind_target("unix://   ").is_err());
    }

    // ── parse_tcp_bind_target ──

    #[test]
    fn parse_tcp_bind_target_strips_prefix() {
        match parse_tcp_bind_target("tcp://127.0.0.1:3000", "tcp://127.0.0.1:3000")
            .expect("should strip tcp prefix")
        {
            BindTarget::Tcp(addr) => assert_eq!(addr.to_string(), "127.0.0.1:3000"),
            #[cfg(unix)]
            BindTarget::Unix(_) => panic!("expected tcp"),
        }
    }

    #[test]
    fn parse_tcp_bind_target_without_prefix() {
        match parse_tcp_bind_target("127.0.0.1:3000", "127.0.0.1:3000")
            .expect("should parse without prefix")
        {
            BindTarget::Tcp(addr) => assert_eq!(addr.to_string(), "127.0.0.1:3000"),
            #[cfg(unix)]
            BindTarget::Unix(_) => panic!("expected tcp"),
        }
    }

    #[test]
    fn parse_tcp_bind_target_invalid() {
        let err = parse_tcp_bind_target("garbage", "garbage");
        assert!(err.is_err());
    }

    // ── prepare_unix_socket_path ──

    #[cfg(unix)]
    #[test]
    fn prepare_unix_socket_rejects_existing_path() {
        // /tmp always exists
        let err = prepare_unix_socket_path(std::path::Path::new("/tmp"));
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("already exists"));
    }

    #[cfg(unix)]
    #[test]
    fn prepare_unix_socket_creates_parent_dirs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sub").join("deep").join("host.sock");
        prepare_unix_socket_path(&path).expect("should create parent dirs");
        assert!(path.parent().unwrap().exists());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_unix_socket_ok_with_existing_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("host.sock");
        prepare_unix_socket_path(&path).expect("should succeed with existing parent");
    }

    // ── map_host_error ──

    #[test]
    fn map_host_error_connector_not_found() {
        let (status, msg) = map_host_error(HostError::ConnectorNotFound("test".into()));
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(msg.contains("connector not found"));
    }

    #[test]
    fn map_host_error_invalid_filter() {
        let (status, msg) = map_host_error(HostError::InvalidFilter("bad".into()));
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("invalid filter"));
    }

    #[test]
    fn map_host_error_preflight_failed() {
        let (status, msg) = map_host_error(HostError::PreflightFailed("denied".into()));
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(msg.contains("preflight failed"));
    }

    #[test]
    fn map_host_error_cache_error() {
        let (status, msg) = map_host_error(HostError::CacheError("stale".into()));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(msg.contains("cache error"));
    }

    #[test]
    fn map_host_error_registry_error() {
        let (status, msg) = map_host_error(HostError::RegistryError("unreachable".into()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(msg.contains("registry error"));
    }

    #[test]
    fn map_host_error_internal() {
        let (status, msg) = map_host_error(HostError::Internal("panic".into()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(msg.contains("internal error"));
    }

    #[test]
    fn map_host_error_unavailable() {
        let (status, msg) = map_host_error(HostError::Unavailable("circuit open".into()));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(msg.contains("unavailable"));
    }

    #[test]
    fn operation_priority_marks_health_as_high() {
        assert_eq!(operation_priority("health"), RequestPriority::High);
        assert_eq!(operation_priority("self_check"), RequestPriority::High);
        assert_eq!(operation_priority("configure"), RequestPriority::Critical);
    }

    #[test]
    fn map_resilience_error_load_shed_to_unavailable() {
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let error = map_resilience_error(
            &connector_id,
            "introspect",
            ResilienceError::LoadShed {
                load_per_mille: 950,
            },
        );
        assert!(matches!(error, HostError::Unavailable(_)));
        assert!(error.to_string().contains("load shed"));
    }

    // ── parse_connector_id ──

    #[test]
    fn parse_connector_id_valid() {
        let id = parse_connector_id("fcp.test:echo:1.0.0").expect("should parse valid id");
        assert_eq!(id.to_string(), "fcp.test:echo:1.0.0");
    }

    #[test]
    fn parse_connector_id_invalid() {
        let (status, msg) = parse_connector_id("").unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("invalid"));
    }

    // ── ConnectorConfig deserialization ──

    #[test]
    fn connector_config_minimal_json() {
        let json = r#"{"id": "fcp.test:echo:1.0.0", "binary": "/usr/bin/echo"}"#;
        let config: ConnectorConfig = serde_json::from_str(json).expect("should parse");
        assert_eq!(config.id, "fcp.test:echo:1.0.0");
        assert_eq!(config.binary, "/usr/bin/echo");
        assert!(config.name.is_none());
        assert!(config.description.is_none());
        assert!(config.args.is_empty());
        assert!(config.env.is_empty());
        assert!(config.config.is_none());
        assert!(config.categories.is_empty());
        assert!(config.version.is_none());
    }

    #[test]
    fn connector_config_full_json() {
        let json = r#"{
            "id": "fcp.test:echo:1.0.0",
            "binary": "/usr/bin/echo",
            "name": "Echo Connector",
            "description": "Echoes input",
            "args": ["--verbose"],
            "env": {"LOG_LEVEL": "debug"},
            "config": {"key": "value"},
            "categories": ["utility", "test"],
            "version": "2.3.4"
        }"#;
        let config: ConnectorConfig = serde_json::from_str(json).expect("should parse");
        assert_eq!(config.name.as_deref(), Some("Echo Connector"));
        assert_eq!(config.description.as_deref(), Some("Echoes input"));
        assert_eq!(config.args, vec!["--verbose"]);
        assert_eq!(config.env.get("LOG_LEVEL").unwrap(), "debug");
        assert!(config.config.is_some());
        assert_eq!(config.categories, vec!["utility", "test"]);
        assert_eq!(config.version.as_deref(), Some("2.3.4"));
    }

    #[test]
    fn cache_validator_from_headers_reads_http_validators() {
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, HeaderValue::from_static("\"etag-123\""));
        headers.insert(
            IF_MODIFIED_SINCE,
            HeaderValue::from_static("Sat, 07 Mar 2026 15:00:00 GMT"),
        );

        let validator = cache_validator_from_headers(&headers).expect("validator from headers");
        assert_eq!(validator.if_none_match.as_deref(), Some("\"etag-123\""));
        assert_eq!(
            validator.if_modified_since,
            Some(Utc.with_ymd_and_hms(2026, 3, 7, 15, 0, 0).unwrap())
        );
    }

    #[test]
    fn merge_cache_validator_prefers_payload_and_fills_missing_header_fields() {
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, HeaderValue::from_static("\"etag-header\""));
        headers.insert(
            IF_MODIFIED_SINCE,
            HeaderValue::from_static("Sat, 07 Mar 2026 15:00:00 GMT"),
        );

        let merged = merge_cache_validator(
            Some(CacheValidator {
                if_none_match: Some("\"etag-body\"".to_string()),
                if_modified_since: None,
            }),
            &headers,
        )
        .expect("merged validator");

        assert_eq!(merged.if_none_match.as_deref(), Some("\"etag-body\""));
        assert_eq!(
            merged.if_modified_since,
            Some(Utc.with_ymd_and_hms(2026, 3, 7, 15, 0, 0).unwrap())
        );
    }

    #[test]
    fn cache_headers_emit_http_cache_metadata() {
        let cache = CacheMetadata {
            etag: "\"etag-123\"".to_string(),
            last_modified: Utc.with_ymd_and_hms(2026, 3, 7, 15, 0, 0).unwrap(),
            max_age_seconds: 300,
            stale_while_revalidate_seconds: Some(60),
        };

        let headers = cache_headers(Some(&cache));
        assert_eq!(headers.get(ETAG).unwrap(), "\"etag-123\"");
        assert_eq!(
            headers.get(LAST_MODIFIED).unwrap(),
            "Sat, 07 Mar 2026 15:00:00 GMT"
        );
        assert_eq!(
            headers.get(CACHE_CONTROL).unwrap(),
            "max-age=300, stale-while-revalidate=60"
        );
        assert_eq!(
            headers.get(VARY).unwrap(),
            "If-None-Match, If-Modified-Since"
        );
    }

    #[test]
    fn connector_config_array_json() {
        let json = r#"[
            {"id": "fcp.a:b:1.0.0", "binary": "/bin/a"},
            {"id": "fcp.c:d:1.0.0", "binary": "/bin/c"}
        ]"#;
        let configs: Vec<ConnectorConfig> = serde_json::from_str(json).expect("should parse");
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].id, "fcp.a:b:1.0.0");
        assert_eq!(configs[1].id, "fcp.c:d:1.0.0");
    }

    // ── BindTarget debug ──

    #[test]
    fn bind_target_debug_tcp() {
        let target = BindTarget::Tcp("127.0.0.1:9090".parse().unwrap());
        let dbg = format!("{target:?}");
        assert!(dbg.contains("Tcp"));
        assert!(dbg.contains("9090"));
    }

    #[cfg(unix)]
    #[test]
    fn bind_target_debug_unix() {
        let target = BindTarget::Unix(std::path::PathBuf::from("/tmp/test.sock"));
        let dbg = format!("{target:?}");
        assert!(dbg.contains("Unix"));
        assert!(dbg.contains("test.sock"));
    }

    // ── SubprocessRegistry version() ──

    #[test]
    fn subprocess_registry_version() {
        let registry = SubprocessRegistry {
            connectors: HashMap::new(),
            _resilience: Arc::new(ResilienceLayer::default()),
            version: 42,
        };
        assert_eq!(registry.version(), 42);
    }

    #[test]
    fn subprocess_registry_clone() {
        let registry = SubprocessRegistry {
            connectors: HashMap::new(),
            _resilience: Arc::new(ResilienceLayer::default()),
            version: 7,
        };
        let cloned = registry.clone();
        assert_eq!(cloned.version(), 7);
        assert!(cloned.connectors.is_empty());
    }

    // ── AppState clone ──

    #[fcp_async_core::runtime::test]
    async fn app_state_clone_preserves_started_at() {
        let registry = Arc::new(SubprocessRegistry {
            connectors: HashMap::new(),
            _resilience: Arc::new(ResilienceLayer::default()),
            version: 1,
        });
        let doctor = DoctorService::new(Arc::clone(&registry));
        let discovery = Arc::new(DiscoveryEndpoint::new(
            Arc::clone(&registry),
            Arc::new(BudgetPolicyEngine::new()),
        ));
        let lifecycle = Arc::new(HostLifecycleManager::new());
        let rollout = Arc::new(RolloutController::new(
            Arc::clone(&registry),
            Arc::clone(&lifecycle),
        ));
        let state = AppState {
            registry,
            doctor,
            discovery,
            cancellation: Arc::new(CancellationController::new()),
            lifecycle,
            rollout,
            supply_chain: Arc::new(SupplyChainGate::default()),
            started_at: Instant::now(),
        };
        let cloned = state.clone();
        // started_at should be equal (same instant)
        assert_eq!(state.started_at, cloned.started_at);
    }

    // ── ConnectorSummary defaults in SubprocessConnector ──

    #[test]
    fn connector_config_defaults_name_to_id() {
        let json = r#"{"id": "fcp.test:echo:1.0.0", "binary": "/bin/echo"}"#;
        let config: ConnectorConfig = serde_json::from_str(json).expect("parse");
        assert!(config.name.is_none());
        // When name is None, SubprocessConnector::spawn would use connector_id.to_string()
    }

    #[test]
    fn connector_config_defaults_version_none() {
        let json = r#"{"id": "fcp.test:echo:1.0.0", "binary": "/bin/echo"}"#;
        let config: ConnectorConfig = serde_json::from_str(json).expect("parse");
        assert!(config.version.is_none());
        // When version is None, SubprocessConnector::spawn defaults to 1.0.0
    }

    #[test]
    fn connector_config_debug() {
        let config = ConnectorConfig {
            id: "fcp.test:echo:1.0.0".to_string(),
            binary: "/bin/echo".to_string(),
            name: None,
            description: None,
            args: vec![],
            env: HashMap::new(),
            config: None,
            categories: vec![],
            version: None,
        };
        let dbg = format!("{config:?}");
        assert!(dbg.contains("ConnectorConfig"));
        assert!(dbg.contains("fcp.test:echo:1.0.0"));
    }
}
