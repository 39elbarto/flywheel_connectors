//! Minimal fcp-host HTTP server (doctor endpoint).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use fcp_core::{
    ConnectorHealth, ConnectorId, HealthSnapshot, Introspection, RequestId, SafetyTier,
    SelfCheckReport,
};
use fcp_host::{
    ConnectorArchetype, ConnectorRegistry, ConnectorSummary, DoctorReport, DoctorRequest,
    DoctorService,
};
use fcp_host::{HostError, HostResult};
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

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

        let stderr_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
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

#[tokio::main]
async fn main() -> HostResult<()> {
    let addr: SocketAddr = std::env::var("FCP_HOST_BIND")
        .unwrap_or_else(|_| "127.0.0.1:9090".to_string())
        .parse()
        .map_err(|err| HostError::Internal(format!("invalid bind address: {err}")))?;

    let configs = load_connector_configs()?;
    if configs.is_empty() {
        tracing::warn!("no connectors configured; doctor self-checks will fail");
    }

    let registry = Arc::new(SubprocessRegistry::from_configs(configs).await?);
    let service = match resolve_self_check_timeout()? {
        Some(timeout) => DoctorService::with_timeout(Arc::clone(&registry), timeout),
        None => DoctorService::new(Arc::clone(&registry)),
    };

    let app = Router::new()
        .route("/doctor", post(doctor_handler::<SubprocessRegistry>))
        .with_state(service);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|err| HostError::Internal(format!("bind error: {err}")))?;

    tracing::info!(%addr, "fcp-host listening");
    axum::serve(listener, app)
        .await
        .map_err(|err| HostError::Internal(format!("server error: {err}")))?;

    Ok(())
}

async fn doctor_handler<R: ConnectorRegistry>(
    State(service): State<DoctorService<R>>,
    Json(request): Json<DoctorRequest>,
) -> Result<Json<DoctorReport>, (StatusCode, String)> {
    match service.handle(request).await {
        Ok(report) => Ok(Json(report)),
        Err(err) => Err(map_host_error(err)),
    }
}

fn map_host_error(err: HostError) -> (StatusCode, String) {
    match err {
        HostError::ConnectorNotFound(_) => (StatusCode::NOT_FOUND, err.to_string()),
        HostError::InvalidFilter(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}
