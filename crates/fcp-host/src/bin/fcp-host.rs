//! Minimal fcp-host HTTP server with discovery and doctor endpoints.

use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use fcp_async_core::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use fcp_async_core::net::TcpListener;
use fcp_async_core::process::{Child, ChildStdin, ChildStdout, Command};
use fcp_async_core::sync::Mutex;
use fcp_async_core::task::{self, JoinHandle};
use fcp_core::{
    ConnectorHealth, ConnectorId, HealthSnapshot, Introspection, RequestId, SafetyTier,
    SelfCheckReport,
};
use fcp_host::{
    BudgetPolicyEngine, ConnectorArchetype, ConnectorRegistry, ConnectorSummary, DiscoveryEndpoint,
    DiscoveryFilter, DiscoveryResponse, DoctorReport, DoctorRequest, DoctorService,
    HostHealthResponse, HostHealthStatus, IntrospectionResponse, PreflightRequest,
    PreflightResponse,
};
use fcp_host::{HostError, HostResult};
use serde::Deserialize;
use serde_json::json;
#[cfg(unix)]
use tokio::net::UnixListener;

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
}

impl SubprocessConnector {
    async fn spawn(config: ConnectorConfig) -> HostResult<Self> {
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
        };

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
        let mut runner = self.runner.lock().await;
        let request = json!({
            "jsonrpc": "2.0",
            "id": RequestId::random().0,
            "method": method,
            "params": params,
        });
        let response = runner
            .request(&request)
            .await
            .map_err(|err| HostError::RegistryError(format!("connector IO error: {err}")))?;
        if let Some(error) = response.get("error") {
            return Err(HostError::RegistryError(format!(
                "connector error: {error}"
            )));
        }
        Ok(response.get("result").cloned().unwrap_or(json!({})))
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

    async fn summary_with_health(&self) -> ConnectorSummary {
        let mut summary = self.summary.clone();
        match self.health().await {
            Ok(snapshot) => {
                summary.health = ConnectorHealth::from(&snapshot.status);
                summary.last_health_check = Some(chrono::Utc::now());
            }
            Err(err) => {
                summary.health =
                    ConnectorHealth::unavailable(format!("health check failed: {err}"));
                summary.last_health_check = Some(chrono::Utc::now());
            }
        }
        summary
    }
}

#[derive(Clone)]
struct SubprocessRegistry {
    connectors: HashMap<ConnectorId, Arc<SubprocessConnector>>,
    version: u64,
}

impl SubprocessRegistry {
    async fn from_configs(configs: Vec<ConnectorConfig>) -> HostResult<Self> {
        let mut map = HashMap::new();
        for config in configs {
            let connector = SubprocessConnector::spawn(config).await?;
            map.insert(connector.summary.id.clone(), Arc::new(connector));
        }
        Ok(Self {
            connectors: map,
            version: 1,
        })
    }
}

#[async_trait::async_trait]
impl ConnectorRegistry for SubprocessRegistry {
    async fn list(&self) -> Vec<ConnectorSummary> {
        let mut results = Vec::new();
        for connector in self.connectors.values() {
            results.push(connector.summary_with_health().await);
        }
        results
    }

    async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
        self.connectors
            .get(id)
            .map(|connector| connector.summary.clone())
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
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        for (key, value) in env {
            cmd.env(key, value);
        }

        let mut child = cmd.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("connector stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("connector stdout unavailable"))?;
        let stderr = child
            .stderr
            .take()
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

#[derive(Clone)]
struct AppState {
    registry: Arc<SubprocessRegistry>,
    doctor: DoctorService<SubprocessRegistry>,
    discovery: Arc<DiscoveryEndpoint<SubprocessRegistry, BudgetPolicyEngine>>,
    started_at: Instant,
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
    match fcp_async_core::runtime::block_on_sync(async_main()) {
        Ok(result) => result,
        Err(err) => Err(HostError::Internal(format!(
            "runtime bootstrap failed: {err}"
        ))),
    }
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
    let state = Arc::new(AppState {
        registry,
        doctor,
        discovery,
        started_at: Instant::now(),
    });

    let app = Router::new()
        .route("/doctor", post(doctor_handler))
        .route("/rpc/discover", post(discover_handler))
        .route("/rpc/introspect/{connector_id}", get(introspect_handler))
        .route("/rpc/preflight", post(preflight_handler))
        .route("/rpc/health", get(health_handler))
        .with_state(state);

    match bind_target {
        BindTarget::Tcp(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|err| HostError::Internal(format!("tcp bind error: {err}")))?;
            tracing::info!(transport = "tcp", %addr, "fcp-host listening");
            axum::serve(listener, app)
                .await
                .map_err(|err| HostError::Internal(format!("server error: {err}")))?;
        }
        #[cfg(unix)]
        BindTarget::Unix(path) => {
            prepare_unix_socket_path(&path)?;
            let listener = UnixListener::bind(&path)
                .map_err(|err| HostError::Internal(format!("unix bind error: {err}")))?;
            tracing::info!(
                transport = "unix",
                socket_path = %path.display(),
                "fcp-host listening"
            );
            axum::serve(listener, app)
                .await
                .map_err(|err| HostError::Internal(format!("server error: {err}")))?;
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
    Json(filter): Json<Option<DiscoveryFilter>>,
) -> Json<DiscoveryResponse> {
    let started_at = Instant::now();
    tracing::debug!(
        event = "discover_request",
        filter = ?filter,
        "processing discovery request"
    );
    let response = state.discovery.discover(filter).await;
    tracing::debug!(
        event = "discover_response",
        connector_count = response.connectors.len(),
        registry_version = response.registry_version,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "discovery request complete"
    );
    Json(response)
}

async fn introspect_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
) -> Result<Json<IntrospectionResponse>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "introspect_request",
        connector_id = %connector_id,
        "processing introspection request"
    );
    match state.discovery.introspect(&connector_id).await {
        Ok(response) => {
            tracing::debug!(
                event = "introspect_response",
                connector_id = %connector_id,
                tool_count = response.tools.len(),
                duration_ms = started_at.elapsed().as_millis() as u64,
                "introspection request complete"
            );
            Ok(Json(response))
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

fn parse_connector_id(raw: &str) -> Result<ConnectorId, (StatusCode, String)> {
    raw.parse().map_err(|err| {
        map_host_error(HostError::InvalidFilter(format!(
            "invalid connector id '{raw}': {err}"
        )))
    })
}

fn map_host_error(err: HostError) -> (StatusCode, String) {
    match err {
        HostError::ConnectorNotFound(_) => (StatusCode::NOT_FOUND, err.to_string()),
        HostError::InvalidFilter(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        HostError::PreflightFailed(_) => (StatusCode::FORBIDDEN, err.to_string()),
        HostError::CacheError(_) => (StatusCode::SERVICE_UNAVAILABLE, err.to_string()),
        HostError::RegistryError(_) | HostError::Internal(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            version: 42,
        };
        assert_eq!(registry.version(), 42);
    }

    #[test]
    fn subprocess_registry_clone() {
        let registry = SubprocessRegistry {
            connectors: HashMap::new(),
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
            version: 1,
        });
        let doctor = DoctorService::new(Arc::clone(&registry));
        let discovery = Arc::new(DiscoveryEndpoint::new(
            Arc::clone(&registry),
            Arc::new(BudgetPolicyEngine::new()),
        ));
        let state = AppState {
            registry,
            doctor,
            discovery,
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
