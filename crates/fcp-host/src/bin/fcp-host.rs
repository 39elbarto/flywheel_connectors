//! Minimal fcp-host HTTP server (doctor endpoint).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use fcp_core::{ConnectorId, Introspection, SelfCheckReport};
use fcp_host::{
    ConnectorArchetype, ConnectorRegistry, ConnectorSummary, DoctorRequest, DoctorService,
};
use fcp_host::{HostError, HostResult};

#[derive(Clone)]
struct StubRegistry;

#[async_trait::async_trait]
impl ConnectorRegistry for StubRegistry {
    async fn list(&self) -> Vec<ConnectorSummary> {
        Vec::new()
    }

    async fn get(&self, _id: &ConnectorId) -> Option<ConnectorSummary> {
        None
    }

    async fn get_introspection(&self, _id: &ConnectorId) -> Option<Introspection> {
        None
    }

    async fn get_archetype(&self, _id: &ConnectorId) -> Option<ConnectorArchetype> {
        None
    }

    async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<fcp_core::RateLimitDeclarations> {
        None
    }

    async fn self_check(&self, _id: &ConnectorId) -> Option<SelfCheckReport> {
        Some(SelfCheckReport::unsupported())
    }

    fn version(&self) -> u64 {
        1
    }
}

#[tokio::main]
async fn main() -> HostResult<()> {
    let addr: SocketAddr = std::env::var("FCP_HOST_BIND")
        .unwrap_or_else(|_| "127.0.0.1:9090".to_string())
        .parse()
        .map_err(|err| HostError::Internal(format!("invalid bind address: {err}")))?;

    let registry = Arc::new(StubRegistry);
    let service = DoctorService::new(Arc::clone(&registry));

    let app = Router::new()
        .route("/doctor", post(doctor_handler::<StubRegistry>))
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
) -> Result<Json<fcp_host::DoctorReport>, (StatusCode, String)> {
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
