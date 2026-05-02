//! Minimal fcp-host HTTP server with discovery and doctor endpoints.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::Path as FsPath;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{
        HeaderMap, HeaderValue, Request, StatusCode,
        header::{CACHE_CONTROL, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, VARY},
    },
    middleware::{Next, from_fn_with_state},
    response::Response,
    routing::{get, post},
};
use base64::Engine;
use chrono::{DateTime, Utc};
use fcp_async_core::channel::{mpsc, oneshot};
use fcp_async_core::hyper_bridge::{HyperExecutor, HyperIo};
use fcp_async_core::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use fcp_async_core::net::TcpListener;
#[cfg(unix)]
use fcp_async_core::net::UnixListener;
use fcp_async_core::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use fcp_async_core::sync::{Mutex, RwLock};
use fcp_async_core::task::{self, JoinHandle};
use fcp_crypto::{
    canonicalize::to_deterministic_cbor,
    cose::fcp2_claims,
    ed25519::{Ed25519Signature, Ed25519VerifyingKey, PUBLIC_KEY_SIZE},
    kid::KeyId,
};
#[cfg(test)]
use fcp_evidence::{AttestationChain, CascadeConfig, CascadeHop, RevocationRecord};
use fcp_evidence::{
    FcpCryptoMlDsa65Verifier, HybridOwnerObjectKind, HybridOwnerObjectSignatures,
    HybridOwnerObjectTranscript, MlDsa65VerifyingKeyBytes, OwnerKeyMigrationAttestation,
    OwnerMigrationVerificationContext, SoftwareBillOfMaterials, SupplyChainAttestation,
    TrustedV3OwnerMap, verify_hybrid_owner_object,
};
use fcp_host::{
    BatchExecutor, BatchInvokeRequest, BatchInvokeResponse, BatchOperation, BatchOperationError,
    BatchOptions, BatchStatus, BudgetAction, BudgetPolicyEngine, BudgetReportRequest,
    BudgetReportResponse, CacheMetadata, CacheValidator, CancellationController,
    CancellationRequest, CancellationResponse, CapabilityTokenVerifyRequest, ConfigRevisionRecord,
    ConnectorAdminState, ConnectorAdminStatus, ConnectorArchetype,
    ConnectorArtifactMetadataResponse, ConnectorArtifactRegistrationRequest,
    ConnectorArtifactRegistrationResponse, ConnectorConfigApplyRequest,
    ConnectorConfigApplyResponse, ConnectorConfigDiffRequest, ConnectorConfigDiffResponse,
    ConnectorConfigRevisionsResponse, ConnectorConfigRollbackRequest, ConnectorConfigSnapshot,
    ConnectorConfigSnapshotSource, ConnectorConfigValidateRequest, ConnectorConfigValidateResponse,
    ConnectorInventoryApplyReport, ConnectorInventoryMutationKind,
    ConnectorInventoryMutationRequest, ConnectorInventoryMutationResponse,
    ConnectorInventoryResponse, ConnectorRegistry, ConnectorSummary, DiscoveryEndpoint,
    DiscoveryFilter, DiscoveryResponse, DoctorReport, DoctorRequest, DoctorService,
    EventAcknowledgeRequest, EventAcknowledgeResponse, EventQueryRequest, EventQueryResponse,
    GateOutcome, HostAdminStateStore, HostHealthResponse, HostHealthStatus, HostPreflightRequest,
    HostSimulateRequest, HostSimulateResponse, IntrospectionResponse, JournalQueryRequest,
    JournalQueryResponse, LifecycleTransitionRequest, LifecycleTransitionResponse, LogQueryRequest,
    LogQueryResponse, ManagedConnectorConfig, MeshQuorumSignals, OperationResult,
    OperationResultStatus, PreflightRequest, PreflightResponse, ReceiptQueryRequest,
    ReceiptQueryResponse, ReceiptSummary, RequestPriority, ResilienceError, ResilienceLayer,
    RevocationCascadeVerifier, RolloutController, RolloutDecision, RolloutObservation,
    RolloutOutcome, SafetyTierExt, SanitizedConnectorConfig, SimulateCostConfidence,
    SimulateCostEstimate, SimulatePhase, SimulateReceipt, SimulateReceiptQueryRequest,
    SimulateReceiptQueryResponse, SimulateResourceAvailability, StartupReconciliationReport,
    SupplyChainGate, SupplyChainGateConfig, ToolDescriptor, admit_safety_tier,
    capability_constraint_audit_descriptor, classify_deployment_mode, diff_sanitized_config_values,
    emit_boot_log, emit_capability_constraint_denial_audit_event, merge_connector_health,
};
use fcp_host::{DeploymentClassification, DeploymentTierRefusal, HostError, HostResult};
use fcp_kernel::{
    ApprovalMode, ConnectorHealth, ConnectorId, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, Introspection, InvokeRequest, InvokeResponse, InvokeStatus, LifecycleError,
    LifecycleManager, LifecycleState, LifecycleStatus, LimitType, RateLimitDeclarations,
    RateLimitEnforcement, RateLimitPool, RateLimitScope, RateLimitUnit, RequestId, SelfCheckReport,
    SimulateRequest, SimulateResponse,
};
use fcp_policy::{
    CapabilityConstraintEnforcer, ConstraintEvaluation, DefaultConstraintEnforcer,
    OperationalModelSelection, PrincipalId, RequestDescriptor,
    TRUTH_PRECEDENCE_ACCEPT_DEGRADED_SINGLE_HOST_ENV, TRUTH_PRECEDENCE_DEFAULT_ENV,
    select_operational_model_from_env_for_deployment,
};
use fcp_prelude::{
    ApprovalToken, CapabilityConstraints, CapabilityVerifier, CostEstimateConfidence, Decision,
    LeasePurpose as CoreLeasePurpose, ObjectId, PolicySimulationInput, ResourceAvailability,
    RolloutPolicy, SafetyTier, TailscaleNodeId, TransportMode, UsageMetric, UsageMetricKind,
    ZoneId, ZonePolicyObject, simulate_policy_decision,
};
#[cfg(test)]
use fcp_prelude::{DecisionReceiptPolicy, ObjectHeader, Provenance, ZoneTransportPolicy};
use fcp_ratelimit::{BackpressureThresholds, TokenBucket};
use futures_util::future::join_all;
use hyper::body::Incoming;
use hyper_util::{
    server::conn::auto::Builder as HyperConnectionBuilder, service::TowerToHyperService,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tower::ServiceExt;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

type ConnectorConfig = ManagedConnectorConfig;

const HYBRID_OWNER_EVIDENCE_TAG: &str = "fcp.hybrid_owner.evidence_cbor";
const HYBRID_OWNER_CONTEXT_FILE_ENV: &str = "FCP_HOST_HYBRID_OWNER_CONTEXT_FILE";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HybridOwnerInvokeEvidence {
    signatures: HybridOwnerObjectSignatures,
    migration_attestation: OwnerKeyMigrationAttestation,
    v4_verifying_key: MlDsa65VerifyingKeyBytes,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HybridOwnerProductionConfig {
    trusted_v3_owner_keys: Vec<Ed25519VerifyingKey>,
    prior_v3_attestation_bytes: Vec<u8>,
    new_v4_attestation_bytes: Vec<u8>,
    #[serde(default)]
    last_accepted_migration_epoch: u64,
}

#[derive(Debug, Clone)]
struct HybridOwnerProductionVerifier {
    trusted_v3_owner_keys: Vec<Ed25519VerifyingKey>,
    prior_v3_attestation_bytes: Vec<u8>,
    new_v4_attestation_bytes: Vec<u8>,
    last_accepted_migration_epoch: u64,
}

impl HybridOwnerProductionVerifier {
    fn new(
        trusted_v3_owner_keys: Vec<Ed25519VerifyingKey>,
        prior_v3_attestation_bytes: Vec<u8>,
        new_v4_attestation_bytes: Vec<u8>,
        last_accepted_migration_epoch: u64,
    ) -> Self {
        Self {
            trusted_v3_owner_keys,
            prior_v3_attestation_bytes,
            new_v4_attestation_bytes,
            last_accepted_migration_epoch,
        }
    }

    fn from_config(config: HybridOwnerProductionConfig) -> Self {
        Self::new(
            config.trusted_v3_owner_keys,
            config.prior_v3_attestation_bytes,
            config.new_v4_attestation_bytes,
            config.last_accepted_migration_epoch,
        )
    }

    fn migration_context(&self) -> OwnerMigrationVerificationContext {
        OwnerMigrationVerificationContext::new(
            TrustedV3OwnerMap::from_keys(self.trusted_v3_owner_keys.iter().cloned()),
            self.prior_v3_attestation_bytes.clone(),
            self.new_v4_attestation_bytes.clone(),
            self.last_accepted_migration_epoch,
            Utc::now().timestamp().try_into().unwrap_or(0),
        )
    }

    fn verify_capability_token(
        &self,
        zone_id: &ZoneId,
        token: &fcp_core::CapabilityToken,
        evidence: &HybridOwnerInvokeEvidence,
    ) -> HostResult<()> {
        let payload = token.raw().to_cbor().map_err(|error| {
            HostError::PreflightFailed(format!(
                "hybrid owner capability token payload serialization failed: {error}"
            ))
        })?;
        let transcript = HybridOwnerObjectTranscript::new(
            HybridOwnerObjectKind::CapabilityToken,
            zone_id.clone(),
            &payload,
        );
        verify_hybrid_owner_object(
            &transcript,
            &evidence.signatures,
            &evidence.migration_attestation,
            &evidence.v4_verifying_key,
            &self.migration_context(),
            &FcpCryptoMlDsa65Verifier,
        )
        .map(|_| ())
        .map_err(|error| {
            HostError::PreflightFailed(format!("hybrid owner capability token rejected: {error}"))
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliAction {
    Run,
    PrintHelp,
    PrintVersion,
}

struct SubprocessConnector {
    summary: ConnectorSummary,
    runner_tx: mpsc::Sender<ConnectorRpcRequest>,
    _runner_task: JoinHandle<()>,
    resilience: Arc<ResilienceLayer>,
    capability_verifying_key: Option<[u8; PUBLIC_KEY_SIZE]>,
    handshaken_zone: Mutex<Option<ZoneId>>,
}

#[derive(Debug)]
struct ConnectorRpcRequest {
    method: String,
    params: serde_json::Value,
    response_tx: oneshot::Sender<std::io::Result<serde_json::Value>>,
}

impl SubprocessConnector {
    async fn spawn(
        config: ConnectorConfig,
        resilience: Arc<ResilienceLayer>,
        capability_verifying_key: Option<[u8; PUBLIC_KEY_SIZE]>,
    ) -> HostResult<Self> {
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
        let (runner_tx, mut runner_rx) =
            mpsc::channel::<ConnectorRpcRequest>(CONNECTOR_RPC_QUEUE_CAPACITY);
        let runner_task = task::spawn(async move {
            let mut runner = runner;
            while let Some(request) = runner_rx.recv().await {
                let response = runner.request(&request.method, request.params).await;
                let _ = request.response_tx.send(response);
            }
        });

        let connector = Self {
            summary,
            runner_tx,
            _runner_task: runner_task,
            resilience,
            capability_verifying_key,
            handshaken_zone: Mutex::new(None),
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
                let (response_tx, response_rx) = oneshot::channel();
                fcp_async_core::time::timeout(
                    CONNECTOR_RPC_IO_TIMEOUT,
                    self.runner_tx.send(ConnectorRpcRequest {
                        method: method.to_string(),
                        params,
                        response_tx,
                    }),
                )
                .await
                .map_err(|_| {
                    HostError::RegistryError(format!(
                        "connector dispatcher queue timed out after {}s",
                        CONNECTOR_RPC_IO_TIMEOUT.as_secs()
                    ))
                })?
                .map_err(|_| {
                    HostError::RegistryError("connector dispatcher unavailable".to_string())
                })?;
                let response = fcp_async_core::time::timeout(CONNECTOR_RPC_IO_TIMEOUT, response_rx)
                    .await
                    .map_err(|_| {
                        HostError::RegistryError(format!(
                            "connector dispatcher response timed out after {}s",
                            CONNECTOR_RPC_IO_TIMEOUT.as_secs()
                        ))
                    })?
                    .map_err(|_| {
                        HostError::RegistryError(
                            "connector dispatcher stopped before replying".to_string(),
                        )
                    })?;
                let response = response.map_err(|err| {
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

    async fn rpc_in_handshaken_zone(
        &self,
        zone: &ZoneId,
        method: &str,
        params: serde_json::Value,
    ) -> HostResult<serde_json::Value> {
        let Some(host_public_key) = self.capability_verifying_key else {
            return self.rpc(method, params).await;
        };

        // br-j1pjg serialized same-zone handshakes, but the lock still
        // dropped before the follow-up invoke/simulate RPC. A later
        // cross-zone caller could then re-handshake the connector and
        // invalidate the earlier caller's zone-bound session before the
        // first real operation was queued. Keep the lock through the
        // zone-bound RPC so the handshake and first invoke/simulate form
        // one critical section.
        //
        // INVARIANT (br-utiw3): no code path called from this function
        // (self.rpc → connector subprocess RPC → response) is permitted
        // to recursively call rpc_in_handshaken_zone() for THIS connector.
        // The async Mutex backing handshaken_zone is non-reentrant, so a
        // recursive call would deadlock the calling task on its own
        // outer guard. The function body below is a closed system over
        // self.rpc only, but if a future change introduces a callback
        // path (e.g. a connector triggering a meta-RPC back into the
        // host), THAT path MUST NOT terminate at rpc_in_handshaken_zone
        // for the same connector id. The trace-span warn at exit makes
        // long lock-hold times observable in production.
        let mut handshaken_zone = self.handshaken_zone.lock().await;
        let _lock_hold_monitor = HandshakenZoneLockHoldMonitor {
            connector_id: self.summary.id.as_str(),
            acquired_at: Instant::now(),
            threshold: HANDSHAKEN_ZONE_LOCK_HOLD_WARN_THRESHOLD,
        };
        if handshaken_zone.as_ref() != Some(zone) {
            let nonce = *blake3::hash(RequestId::random().0.as_bytes()).as_bytes();
            let request = HandshakeRequest {
                protocol_version: "1.0.0".to_string(),
                zone: zone.clone(),
                zone_dir: None,
                host_public_key,
                nonce,
                capabilities_requested: Vec::new(),
                host: None,
                transport_caps: None,
                requested_instance_id: None,
            };
            let handshake_params = serde_json::to_value(request).map_err(|err| {
                HostError::RegistryError(format!("handshake encode error: {err}"))
            })?;
            let response: HandshakeResponse = serde_json::from_value(
                self.rpc("handshake", handshake_params).await?,
            )
            .map_err(|err| HostError::RegistryError(format!("handshake parse error: {err}")))?;
            if response.status != "accepted" {
                return Err(HostError::RegistryError(format!(
                    "handshake rejected by connector '{}': {}",
                    self.summary.id, response.status
                )));
            }
            if response.nonce != nonce {
                return Err(HostError::RegistryError(format!(
                    "handshake nonce mismatch for connector '{}'",
                    self.summary.id
                )));
            }
            *handshaken_zone = Some(zone.clone());
        }

        self.rpc(method, params).await
    }

    async fn self_check(&self) -> HostResult<SelfCheckReport> {
        let result = self.rpc("self_check", json!({})).await?;
        serde_json::from_value(result)
            .map_err(|err| HostError::RegistryError(format!("self_check parse error: {err}")))
    }

    async fn invoke(&self, request: InvokeRequest) -> HostResult<InvokeResponse> {
        let params = serde_json::to_value(&request)
            .map_err(|err| HostError::RegistryError(format!("invoke encode error: {err}")))?;
        let result = self
            .rpc_in_handshaken_zone(&request.zone_id, "invoke", params)
            .await?;
        serde_json::from_value(result)
            .map_err(|err| HostError::RegistryError(format!("invoke parse error: {err}")))
    }

    async fn simulate(&self, request: SimulateRequest) -> HostResult<SimulateResponse> {
        let params = serde_json::to_value(&request)
            .map_err(|err| HostError::RegistryError(format!("simulate encode error: {err}")))?;
        let result = self
            .rpc_in_handshaken_zone(&request.zone_id, "simulate", params)
            .await?;
        serde_json::from_value(result)
            .map_err(|err| HostError::RegistryError(format!("simulate parse error: {err}")))
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
    state: Arc<RwLock<RegistryState>>,
    resilience: Arc<ResilienceLayer>,
    version: Arc<AtomicU64>,
    capability_verifying_key: Option<[u8; PUBLIC_KEY_SIZE]>,
    rate_limiters: Arc<HostRateLimiterStore>,
}

struct RegistryEntry {
    config: ConnectorConfig,
    connector: Arc<SubprocessConnector>,
}

/// br-l9tt6: atomic snapshot of a connector's allow-list governance
/// fields. Captured under a single registry read-lock so the
/// `allowed_zones`, `allowed_operations`, and `enforce_empty_allow_lists`
/// values are guaranteed to come from the SAME admin-state generation.
/// See `SubprocessRegistry::allow_list_snapshot`.
#[derive(Debug, Clone)]
struct AllowListSnapshot {
    allowed_zones: Vec<String>,
    allowed_operations: Vec<String>,
    enforce_empty_allow_lists: bool,
}

#[derive(Default)]
struct RegistryState {
    connectors: HashMap<ConnectorId, RegistryEntry>,
}

struct PreparedRegistryApply {
    next_configs: HashMap<ConnectorId, ConnectorConfig>,
    replacement_entries: HashMap<ConnectorId, RegistryEntry>,
    added: Vec<String>,
    updated: Vec<String>,
    removed: Vec<String>,
    unchanged: Vec<String>,
}

impl PreparedRegistryApply {
    fn changed(&self) -> bool {
        !(self.added.is_empty() && self.updated.is_empty() && self.removed.is_empty())
    }

    fn report(&self, registry_version: u64) -> ConnectorInventoryApplyReport {
        ConnectorInventoryApplyReport {
            added: self.added.clone(),
            updated: self.updated.clone(),
            removed: self.removed.clone(),
            unchanged: self.unchanged.clone(),
            registry_version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HostRateLimitBucketKey {
    connector_id: String,
    zone_id: String,
    pool_id: String,
    scope: String,
    principal_id: Option<String>,
    window_nanos: u128,
    requests: u32,
    burst: Option<u32>,
}

#[derive(Default)]
struct HostRateLimiterStore {
    buckets: StdMutex<HashMap<HostRateLimitBucketKey, Arc<TokenBucket>>>,
}

impl HostRateLimiterStore {
    fn bucket_for(
        &self,
        key: HostRateLimitBucketKey,
        pool: &RateLimitPool,
    ) -> HostResult<Arc<TokenBucket>> {
        let mut buckets = self.buckets.lock().map_err(|_| {
            HostError::Internal("host rate-limit bucket store mutex poisoned".to_string())
        })?;
        if let Some(bucket) = buckets.get(&key) {
            return Ok(Arc::clone(bucket));
        }

        let config = rate_limiter_config_from_pool(pool)?;
        let bucket = Arc::new(TokenBucket::from_config(&config));
        buckets.insert(key, Arc::clone(&bucket));
        Ok(bucket)
    }
}

fn rate_limiter_config_from_pool(
    pool: &RateLimitPool,
) -> HostResult<fcp_ratelimit::RateLimitConfig> {
    let mut config = fcp_ratelimit::RateLimitConfig::new(pool.config.requests, pool.config.window);
    if let Some(burst) = pool.config.burst {
        let capacity = pool.config.requests.checked_add(burst).ok_or_else(|| {
            HostError::PreflightFailed(format!(
                "rate limit pool `{}` has overflowed burst capacity",
                pool.id
            ))
        })?;
        config = config.with_burst(capacity);
    }
    Ok(config)
}

fn limit_type_for_unit(unit: RateLimitUnit) -> LimitType {
    match unit {
        RateLimitUnit::Requests => LimitType::Rpm,
        RateLimitUnit::Tokens | RateLimitUnit::Bytes | RateLimitUnit::Custom => LimitType::Quota,
    }
}

fn rate_limit_scope_label(scope: RateLimitScope) -> &'static str {
    match scope {
        RateLimitScope::Instance => "instance",
        RateLimitScope::Credential => "credential",
        RateLimitScope::Global => "global",
    }
}

impl SubprocessRegistry {
    async fn from_configs(
        configs: Vec<ConnectorConfig>,
        capability_verifying_key: Option<[u8; PUBLIC_KEY_SIZE]>,
    ) -> HostResult<Self> {
        let resilience = Arc::new(ResilienceLayer::default());
        let mut map = HashMap::new();
        for config in configs {
            let connector_id: ConnectorId = config.id.parse().map_err(|err| {
                HostError::InvalidFilter(format!("invalid connector id '{}': {err}", config.id))
            })?;
            if map.contains_key(&connector_id) {
                return Err(HostError::InvalidFilter(format!(
                    "duplicate connector id in managed inventory: {connector_id}"
                )));
            }
            let connector = Arc::new(
                SubprocessConnector::spawn(
                    config.clone(),
                    Arc::clone(&resilience),
                    capability_verifying_key,
                )
                .await?,
            );
            map.insert(connector_id, RegistryEntry { config, connector });
        }
        Ok(Self {
            state: Arc::new(RwLock::new(RegistryState { connectors: map })),
            resilience,
            version: Arc::new(AtomicU64::new(1)),
            capability_verifying_key,
            rate_limiters: Arc::new(HostRateLimiterStore::default()),
        })
    }

    async fn inventory(&self) -> Vec<ConnectorConfig> {
        let state = self.state.read().await;
        state
            .connectors
            .values()
            .map(|entry| entry.config.clone())
            .collect()
    }

    async fn prepare_configs(
        &self,
        configs: Vec<ConnectorConfig>,
    ) -> HostResult<PreparedRegistryApply> {
        let current_configs = {
            let state = self.state.read().await;
            state
                .connectors
                .iter()
                .map(|(id, entry)| (id.clone(), entry.config.clone()))
                .collect::<HashMap<_, _>>()
        };

        let mut next_configs = HashMap::new();
        for config in configs {
            let connector_id: ConnectorId = config.id.parse().map_err(|err| {
                HostError::InvalidFilter(format!("invalid connector id '{}': {err}", config.id))
            })?;
            if next_configs.insert(connector_id.clone(), config).is_some() {
                return Err(HostError::InvalidFilter(format!(
                    "duplicate connector id in managed inventory: {connector_id}"
                )));
            }
        }

        let mut replacement_entries = HashMap::new();
        let mut added = Vec::new();
        let mut updated = Vec::new();
        let mut unchanged = Vec::new();

        for (connector_id, config) in &next_configs {
            match current_configs.get(connector_id) {
                Some(current) if current == config => {
                    unchanged.push(connector_id.to_string());
                }
                Some(_) => {
                    let connector = Arc::new(
                        SubprocessConnector::spawn(
                            config.clone(),
                            Arc::clone(&self.resilience),
                            self.capability_verifying_key,
                        )
                        .await?,
                    );
                    replacement_entries.insert(
                        connector_id.clone(),
                        RegistryEntry {
                            config: config.clone(),
                            connector,
                        },
                    );
                    updated.push(connector_id.to_string());
                }
                None => {
                    let connector = Arc::new(
                        SubprocessConnector::spawn(
                            config.clone(),
                            Arc::clone(&self.resilience),
                            self.capability_verifying_key,
                        )
                        .await?,
                    );
                    replacement_entries.insert(
                        connector_id.clone(),
                        RegistryEntry {
                            config: config.clone(),
                            connector,
                        },
                    );
                    added.push(connector_id.to_string());
                }
            }
        }

        let removed = current_configs
            .keys()
            .filter(|connector_id| !next_configs.contains_key(*connector_id))
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();

        Ok(PreparedRegistryApply {
            next_configs,
            replacement_entries,
            added,
            updated,
            removed,
            unchanged,
        })
    }

    async fn preview_configs(
        &self,
        configs: Vec<ConnectorConfig>,
    ) -> HostResult<ConnectorInventoryApplyReport> {
        let prepared = self.prepare_configs(configs).await?;
        Ok(prepared.report(self.version.load(Ordering::SeqCst)))
    }

    async fn apply_configs(
        &self,
        configs: Vec<ConnectorConfig>,
    ) -> HostResult<ConnectorInventoryApplyReport> {
        let mut prepared = self.prepare_configs(configs).await?;
        let changed = prepared.changed();

        let mut state = self.state.write().await;
        let mut current_entries = std::mem::take(&mut state.connectors);
        let mut next_entries = HashMap::new();
        let next_configs = std::mem::take(&mut prepared.next_configs);
        for (connector_id, _config) in next_configs {
            if let Some(entry) = prepared.replacement_entries.remove(&connector_id) {
                next_entries.insert(connector_id, entry);
            } else if let Some(existing) = current_entries.remove(&connector_id) {
                next_entries.insert(connector_id, existing);
            } else {
                return Err(HostError::Internal(format!(
                    "registry apply prepared no entry for connector {connector_id}"
                )));
            }
        }
        state.connectors = next_entries;
        drop(state);

        let registry_version = if changed {
            self.version.fetch_add(1, Ordering::SeqCst) + 1
        } else {
            self.version.load(Ordering::SeqCst)
        };

        Ok(prepared.report(registry_version))
    }

    async fn invoke(&self, request: InvokeRequest) -> HostResult<InvokeResponse> {
        let connector_id = request.connector_id.clone();
        let connector = {
            let state = self.state.read().await;
            state
                .connectors
                .get(&connector_id)
                .map(|entry| Arc::clone(&entry.connector))
        }
        .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;
        connector.invoke(request).await
    }

    /// br-l9tt6: snapshot the three allow-list governance fields
    /// (`allowed_zones`, `allowed_operations`, `enforce_empty_allow_lists`)
    /// under a SINGLE read-lock acquisition.
    ///
    /// Each individual accessor (`allowed_zones`, `allowed_operations`,
    /// `enforce_empty_allow_lists`) takes its own `state.read().await`,
    /// so callers that needed all three were exposed to a TOCTOU race
    /// between reads: a concurrent admin-state writer could update the
    /// connector entry between the two awaits, letting a request gate
    /// mix a STALE allow-list snapshot with a FRESH `enforce_empty`
    /// flag (or vice-versa). Under the right interleaving the gate
    /// fell through with the operator's OLD permissive list even
    /// though the operator had just clamped to deny-all.
    ///
    /// This helper closes the race by performing all three reads
    /// inside one read-guard scope so the writer cannot interleave.
    /// Production gates in `verify_live_request` MUST use this helper
    /// (one call per request) instead of the per-field accessors.
    /// Returns `None` when the connector is unknown.
    async fn allow_list_snapshot(
        &self,
        connector_id: &ConnectorId,
    ) -> Option<AllowListSnapshot> {
        let state = self.state.read().await;
        state.connectors.get(connector_id).map(|entry| {
            let cfg = &entry.config;
            AllowListSnapshot {
                allowed_zones: cfg.allowed_zones.clone(),
                allowed_operations: cfg.allowed_operations.clone(),
                enforce_empty_allow_lists: cfg.enforce_empty_allow_lists,
            }
        })
    }

    async fn connector_requires_singleton_writer(&self, connector_id: &ConnectorId) -> bool {
        let state = self.state.read().await;
        state
            .connectors
            .get(connector_id)
            .is_some_and(|entry| connector_config_declares_singleton_writer(&entry.config))
    }

    async fn enforce_invoke_rate_limits(
        &self,
        request: &InvokeRequest,
        introspection: &IntrospectionResponse,
        principal: &str,
    ) -> HostResult<()> {
        let operation = introspection
            .introspection
            .operations
            .iter()
            .find(|operation| operation.id == request.operation);
        let mut enforced_declared_pool = false;

        if let Some(declarations) = introspection.rate_limits.as_ref()
            && let Some(pool_ids) = declarations.tool_pool_map.get(request.operation.as_str())
        {
            for pool_id in pool_ids {
                let pool = declarations
                    .limits
                    .iter()
                    .find(|pool| pool.id == *pool_id)
                    .ok_or_else(|| {
                        HostError::PreflightFailed(format!(
                            "rate limit declarations for connector `{}` map operation `{}` to unknown pool `{pool_id}`",
                            request.connector_id,
                            request.operation.as_str()
                        ))
                    })?;
                self.enforce_declared_rate_limit_pool(request, principal, pool)
                    .await?;
                enforced_declared_pool = true;
            }
        }

        if !enforced_declared_pool
            && let Some(rate_limit) = operation.and_then(|operation| operation.rate_limit.as_ref())
        {
            self.enforce_inline_operation_rate_limit(request, principal, rate_limit)
                .await?;
        }

        Ok(())
    }

    async fn enforce_declared_rate_limit_pool(
        &self,
        request: &InvokeRequest,
        principal: &str,
        pool: &RateLimitPool,
    ) -> HostResult<()> {
        if matches!(pool.enforcement, RateLimitEnforcement::Advisory) {
            return Ok(());
        }
        pool.validate().map_err(|error| {
            HostError::PreflightFailed(format!(
                "invalid rate limit pool `{}` for connector `{}`: {error}",
                pool.id, request.connector_id
            ))
        })?;
        self.enforce_rate_limit_pool(request, principal, pool).await
    }

    async fn enforce_inline_operation_rate_limit(
        &self,
        request: &InvokeRequest,
        principal: &str,
        rate_limit: &fcp_core::RateLimit,
    ) -> HostResult<()> {
        rate_limit.validate().map_err(|error| {
            HostError::PreflightFailed(format!(
                "invalid rate limit for connector `{}` operation `{}`: {error}",
                request.connector_id,
                request.operation.as_str()
            ))
        })?;
        let scope = match rate_limit.parsed_scope() {
            fcp_core::OperationRateLimitScope::PerConnector
            | fcp_core::OperationRateLimitScope::PerZone => RateLimitScope::Instance,
            fcp_core::OperationRateLimitScope::PerPrincipal => RateLimitScope::Credential,
        };
        let pool = RateLimitPool {
            id: rate_limit
                .pool_name
                .clone()
                .unwrap_or_else(|| format!("operation:{}", request.operation.as_str())),
            description: format!(
                "Inline rate limit for connector `{}` operation `{}`",
                request.connector_id,
                request.operation.as_str()
            ),
            config: fcp_kernel::RateLimitConfig {
                requests: rate_limit.max,
                window: Duration::from_millis(rate_limit.per_ms),
                burst: rate_limit.burst,
                unit: RateLimitUnit::Requests,
            },
            enforcement: RateLimitEnforcement::Hard,
            scope,
        };
        self.enforce_rate_limit_pool(request, principal, &pool)
            .await
    }

    async fn enforce_rate_limit_pool(
        &self,
        request: &InvokeRequest,
        principal: &str,
        pool: &RateLimitPool,
    ) -> HostResult<()> {
        let principal_id =
            matches!(pool.scope, RateLimitScope::Credential).then(|| principal.to_string());
        let key = HostRateLimitBucketKey {
            connector_id: request.connector_id.to_string(),
            zone_id: request.zone_id.to_string(),
            pool_id: pool.id.clone(),
            scope: rate_limit_scope_label(pool.scope).to_string(),
            principal_id,
            window_nanos: pool.config.window.as_nanos(),
            requests: pool.config.requests,
            burst: pool.config.burst,
        };
        let bucket = self.rate_limiters.bucket_for(key, pool)?;
        let context = fcp_ratelimit::ThrottleContext {
            zone_id: request.zone_id.clone(),
            connector_id: Some(request.connector_id.clone()),
            operation_id: Some(request.operation.clone()),
            limit_type: limit_type_for_unit(pool.config.unit),
        };
        let outcome = fcp_ratelimit::enforce(
            bucket.as_ref(),
            1,
            &context,
            BackpressureThresholds::standard(),
        )
        .await;

        if outcome.allowed {
            return Ok(());
        }
        if matches!(pool.enforcement, RateLimitEnforcement::Soft) {
            tracing::warn!(
                event = "invoke_rate_limit_soft_exceeded",
                connector_id = %request.connector_id,
                operation = %request.operation,
                zone_id = %request.zone_id,
                pool_id = %pool.id,
                retry_after_ms = outcome.backpressure.retry_after_ms,
                "soft host invoke rate limit exceeded; allowing request"
            );
            return Ok(());
        }

        let retry_after_ms = outcome
            .backpressure
            .retry_after_ms
            .or_else(|| {
                outcome
                    .violation
                    .as_ref()
                    .map(|violation| violation.retry_after_ms)
            })
            .unwrap_or(0);
        Err(HostError::PreflightFailed(format!(
            "rate limit pool `{}` exceeded for connector `{}` operation `{}` in zone `{}`; retry after {retry_after_ms} ms",
            pool.id,
            request.connector_id,
            request.operation.as_str(),
            request.zone_id.as_str()
        )))
    }

    async fn simulate(&self, request: SimulateRequest) -> HostResult<SimulateResponse> {
        let connector_id = request.connector_id.clone();
        let connector = {
            let state = self.state.read().await;
            state
                .connectors
                .get(&connector_id)
                .map(|entry| Arc::clone(&entry.connector))
        }
        .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;
        connector.simulate(request).await
    }
}

#[async_trait::async_trait]
impl ConnectorRegistry for SubprocessRegistry {
    async fn list(&self) -> Vec<ConnectorSummary> {
        let connectors = {
            let state = self.state.read().await;
            state
                .connectors
                .values()
                .map(|entry| Arc::clone(&entry.connector))
                .collect::<Vec<_>>()
        };
        let mut results = Vec::new();
        for connector in connectors {
            results.push(connector.summary_snapshot().await);
        }
        results
    }

    async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
        let connector = {
            let state = self.state.read().await;
            state
                .connectors
                .get(id)
                .map(|entry| Arc::clone(&entry.connector))
        }?;
        Some(connector.summary_snapshot().await)
    }

    async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
        let connector = {
            let state = self.state.read().await;
            state
                .connectors
                .get(id)
                .map(|entry| Arc::clone(&entry.connector))
        }?;
        connector.introspect().await.ok()
    }

    async fn get_archetype(&self, id: &ConnectorId) -> Option<ConnectorArchetype> {
        let state = self.state.read().await;
        let entry = state.connectors.get(id)?;
        Some(configured_subprocess_archetype(&entry.config))
    }

    async fn get_rate_limits(&self, id: &ConnectorId) -> Option<RateLimitDeclarations> {
        let state = self.state.read().await;
        let entry = state.connectors.get(id)?;
        configured_subprocess_rate_limits(&entry.config)
    }

    async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
        let connector = {
            let state = self.state.read().await;
            state
                .connectors
                .get(id)
                .map(|entry| Arc::clone(&entry.connector))
        }?;
        Some(match connector.self_check().await {
            Ok(report) => report,
            Err(error) => runtime_self_check_failure_report(&error),
        })
    }

    fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }
}

fn runtime_self_check_failure_report(error: &HostError) -> SelfCheckReport {
    SelfCheckReport::failed(
        "self_check_runtime",
        format!("connector self_check failed: {error}"),
    )
}

fn configured_subprocess_archetype(config: &ConnectorConfig) -> ConnectorArchetype {
    match config
        .env
        .get("FCP_TEST_CONNECTOR_ARCHETYPE")
        .map(String::as_str)
    {
        Some("streaming") => ConnectorArchetype::Streaming,
        Some("bidirectional") => ConnectorArchetype::Bidirectional,
        Some("polling") => ConnectorArchetype::Polling,
        Some("webhook") => ConnectorArchetype::Webhook,
        Some("unknown") => ConnectorArchetype::Unknown,
        Some("request_response") => ConnectorArchetype::RequestResponse,
        None => ConnectorArchetype::Unknown,
        Some(_) => ConnectorArchetype::Unknown,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfiguredRateLimitsSection {
    #[serde(default)]
    pools: Vec<ConfiguredRateLimitPool>,
    #[serde(default)]
    operation_pools: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfiguredRateLimitPool {
    id: String,
    #[serde(default)]
    description: Option<String>,
    requests: u32,
    window_ms: u64,
    #[serde(default)]
    burst: Option<u32>,
    #[serde(default)]
    unit: Option<String>,
    #[serde(default)]
    enforcement: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

impl ConfiguredRateLimitsSection {
    fn into_declarations(self) -> HostResult<RateLimitDeclarations> {
        let limits = self
            .pools
            .into_iter()
            .map(ConfiguredRateLimitPool::into_pool)
            .collect::<HostResult<Vec<_>>>()?;
        let declarations = RateLimitDeclarations {
            limits,
            tool_pool_map: self.operation_pools,
        };
        declarations.validate().map_err(|error| {
            HostError::InvalidFilter(format!("invalid configured rate_limits section: {error}"))
        })?;
        Ok(declarations)
    }
}

impl ConfiguredRateLimitPool {
    fn into_pool(self) -> HostResult<RateLimitPool> {
        let unit = match self.unit.as_deref().unwrap_or("requests") {
            "requests" => RateLimitUnit::Requests,
            "tokens" => RateLimitUnit::Tokens,
            "bytes" => RateLimitUnit::Bytes,
            "custom" => RateLimitUnit::Custom,
            other => {
                return Err(HostError::InvalidFilter(format!(
                    "invalid configured rate limit unit `{other}` for pool `{}`",
                    self.id
                )));
            }
        };
        let enforcement = match self.enforcement.as_deref().unwrap_or("hard") {
            "hard" => RateLimitEnforcement::Hard,
            "soft" => RateLimitEnforcement::Soft,
            "advisory" => RateLimitEnforcement::Advisory,
            other => {
                return Err(HostError::InvalidFilter(format!(
                    "invalid configured rate limit enforcement `{other}` for pool `{}`",
                    self.id
                )));
            }
        };
        let scope = match self.scope.as_deref().unwrap_or("instance") {
            "instance" => RateLimitScope::Instance,
            "credential" => RateLimitScope::Credential,
            "global" => RateLimitScope::Global,
            other => {
                return Err(HostError::InvalidFilter(format!(
                    "invalid configured rate limit scope `{other}` for pool `{}`",
                    self.id
                )));
            }
        };
        let pool = RateLimitPool {
            id: self.id,
            description: self.description.unwrap_or_default(),
            config: fcp_kernel::RateLimitConfig {
                requests: self.requests,
                window: Duration::from_millis(self.window_ms),
                burst: self.burst,
                unit,
            },
            enforcement,
            scope,
        };
        pool.validate().map_err(|error| {
            HostError::InvalidFilter(format!(
                "invalid configured rate limit pool `{}`: {error}",
                pool.id
            ))
        })?;
        Ok(pool)
    }
}

fn parse_configured_rate_limits(value: &Value) -> HostResult<RateLimitDeclarations> {
    if let Ok(declarations) = serde_json::from_value::<RateLimitDeclarations>(value.clone()) {
        declarations.validate().map_err(|error| {
            HostError::InvalidFilter(format!(
                "invalid configured canonical rate_limits declaration: {error}"
            ))
        })?;
        return Ok(declarations);
    }

    let section: ConfiguredRateLimitsSection =
        serde_json::from_value(value.clone()).map_err(|error| {
            HostError::InvalidFilter(format!("invalid configured rate_limits section: {error}"))
        })?;
    section.into_declarations()
}

fn configured_subprocess_rate_limits(config: &ConnectorConfig) -> Option<RateLimitDeclarations> {
    let payload = config.config.as_ref()?;
    let value = payload
        .pointer("/rate_limits")
        .or_else(|| payload.pointer("/rateLimits"))
        .or_else(|| payload.pointer("/budget/rate_limits"))?;
    match parse_configured_rate_limits(value) {
        Ok(declarations) if declarations.is_empty() => None,
        Ok(declarations) => Some(declarations),
        Err(error) => {
            tracing::warn!(
                event = "connector_rate_limits_invalid",
                connector_id = %config.id,
                error = %error,
                "ignoring invalid connector rate-limit declarations"
            );
            None
        }
    }
}

fn connector_config_declares_singleton_writer(config: &ConnectorConfig) -> bool {
    let env_declares = config
        .env
        .get("FCP_CONNECTOR_STATE_MODEL")
        .or_else(|| config.env.get("FCP_HOST_CONNECTOR_STATE_MODEL"))
        .is_some_and(|value| value.trim() == "singleton_writer");
    if env_declares {
        return true;
    }

    let Some(payload) = config.config.as_ref() else {
        return false;
    };
    let model = payload
        .pointer("/state/model")
        .or_else(|| payload.pointer("/state_model"))
        .or_else(|| payload.pointer("/stateModel"))
        .and_then(Value::as_str);
    model == Some("singleton_writer")
}

struct ConnectorProcessRunner {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    _stderr_task: JoinHandle<()>,
    poisoned: bool,
    epoch: u64,
    next_request_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseIdDisposition {
    Matched,
    StaleEpoch,
}

const CONNECTOR_RPC_QUEUE_CAPACITY: usize = 64;
const CONNECTOR_RPC_IO_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTOR_RPC_MAX_STDOUT_LINE_BYTES: usize = 64 * 1024;
const CONNECTOR_RPC_MAX_STDERR_LINE_BYTES: usize = 64 * 1024;

/// Threshold above which `rpc_in_handshaken_zone` emits a warn-level
/// log when releasing the per-connector handshaken-zone Mutex
/// (br-utiw3). Set to ~3× the worst-case lock-hold time given two
/// `CONNECTOR_RPC_IO_TIMEOUT` awaits inside the critical section, so
/// the warn only fires on genuinely pathological contention or a
/// hung connector — not on a normal slow-path handshake.
const HANDSHAKEN_ZONE_LOCK_HOLD_WARN_THRESHOLD: Duration = Duration::from_secs(30);

/// RAII observability guard for the per-connector handshaken-zone
/// Mutex critical section in `rpc_in_handshaken_zone` (br-utiw3).
///
/// The async Mutex backing `handshaken_zone` is held across two awaits
/// (handshake RPC + first invoke/simulate RPC) by intentional design —
/// it keeps the handshake and first real call as one critical section
/// so a cross-zone caller cannot re-handshake the connector between
/// them. Both awaits are bounded by `CONNECTOR_RPC_IO_TIMEOUT`, so the
/// worst-case hold time is ~2× that timeout.
///
/// This guard records the lock acquisition time and emits a warn-level
/// structured log when dropped if the hold exceeded
/// `HANDSHAKEN_ZONE_LOCK_HOLD_WARN_THRESHOLD`. It runs on every return
/// path (including `?` early returns) because it lives on the stack
/// above the lock guard. No production behaviour change — observability
/// only.
struct HandshakenZoneLockHoldMonitor<'a> {
    connector_id: &'a str,
    acquired_at: Instant,
    threshold: Duration,
}

impl Drop for HandshakenZoneLockHoldMonitor<'_> {
    fn drop(&mut self) {
        let elapsed = self.acquired_at.elapsed();
        if elapsed > self.threshold {
            tracing::warn!(
                connector_id = self.connector_id,
                hold_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                threshold_ms = u64::try_from(self.threshold.as_millis()).unwrap_or(u64::MAX),
                "rpc_in_handshaken_zone held handshaken_zone Mutex past warn threshold (br-utiw3)",
            );
        }
    }
}

fn connector_io_timeout_error(phase: &'static str, timeout: Duration) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("connector {phase} timed out after {}s", timeout.as_secs()),
    )
}

fn connector_transport_desynchronized_error(reason: impl Into<String>) -> std::io::Error {
    std::io::Error::other(format!(
        "connector transport desynchronized: {}; restart connector before issuing another RPC",
        reason.into()
    ))
}

fn connector_transport_poisoned_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "connector transport is desynchronized after a previous failed RPC; restart connector before issuing another RPC",
    )
}

fn log_connector_stderr_line(line: &[u8], truncated: bool) {
    let trimmed = String::from_utf8_lossy(line);
    let trimmed = trimmed.trim_end();
    if !trimmed.is_empty() || truncated {
        tracing::warn!(
            connector_stderr = %trimmed,
            connector_stderr_truncated = truncated,
            "connector log"
        );
    }
}

impl ConnectorProcessRunner {
    async fn spawn(
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
    ) -> std::io::Result<Self> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

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
            let mut line = Vec::with_capacity(1024);
            let mut truncated = false;
            loop {
                match reader.read_u8().await {
                    Ok(byte) => {
                        if byte == b'\n' {
                            log_connector_stderr_line(&line, truncated);
                            line.clear();
                            truncated = false;
                        } else if line.len() < CONNECTOR_RPC_MAX_STDERR_LINE_BYTES {
                            line.push(byte);
                        } else {
                            truncated = true;
                        }
                    }
                    Err(err)
                        if err.kind() == std::io::ErrorKind::UnexpectedEof && !line.is_empty() =>
                    {
                        log_connector_stderr_line(&line, truncated);
                        break;
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            _child: child,
            stdin,
            stdout: BufReader::new(stdout),
            _stderr_task: stderr_task,
            poisoned: false,
            epoch: 0,
            next_request_seq: 0,
        })
    }

    fn next_request_id(&mut self) -> String {
        let request_id = format!("{}:{}", self.epoch, self.next_request_seq);
        self.next_request_seq = self.next_request_seq.saturating_add(1);
        request_id
    }

    async fn send_json(
        &mut self,
        value: &serde_json::Value,
        io_timeout: Duration,
    ) -> std::io::Result<()> {
        let line = serde_json::to_string(value)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        fcp_async_core::time::timeout(io_timeout, async {
            self.stdin.write_all(line.as_bytes()).await?;
            self.stdin.write_all(b"\n").await?;
            self.stdin.flush().await
        })
        .await
        .map_err(|_| connector_io_timeout_error("stdin write", io_timeout))??;
        Ok(())
    }

    async fn read_json(&mut self, io_timeout: Duration) -> std::io::Result<serde_json::Value> {
        let mut line = Vec::with_capacity(1024);
        let bytes = fcp_async_core::time::timeout(io_timeout, async {
            loop {
                if line.len() > CONNECTOR_RPC_MAX_STDOUT_LINE_BYTES {
                    return Ok(line.len());
                }
                match self.stdout.read_u8().await {
                    Ok(byte) => {
                        line.push(byte);
                        if byte == b'\n' {
                            return Ok(line.len());
                        }
                    }
                    Err(err)
                        if err.kind() == std::io::ErrorKind::UnexpectedEof && line.is_empty() =>
                    {
                        return Ok(0);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(line.len());
                    }
                    Err(err) => return Err(err),
                }
            }
        })
        .await
        .map_err(|_| connector_io_timeout_error("stdout read", io_timeout))??;
        if bytes == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connector closed stdout",
            ));
        }
        if line.len() > CONNECTOR_RPC_MAX_STDOUT_LINE_BYTES {
            return Err(connector_transport_desynchronized_error(format!(
                "stdout frame exceeded {CONNECTOR_RPC_MAX_STDOUT_LINE_BYTES} bytes"
            )));
        }
        let line = std::str::from_utf8(&line)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        serde_json::from_str::<serde_json::Value>(line.trim())
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    fn validate_response_id(
        expected_id: &str,
        epoch: u64,
        response: &serde_json::Value,
    ) -> std::io::Result<ResponseIdDisposition> {
        let actual_id = response.get("id").ok_or_else(|| {
            connector_transport_desynchronized_error(format!(
                "response missing id for request id {expected_id}"
            ))
        })?;
        if actual_id == expected_id {
            Ok(ResponseIdDisposition::Matched)
        } else if response
            .get("id")
            .and_then(serde_json::Value::as_str)
            .and_then(|id| id.split_once(':'))
            .and_then(|(response_epoch, _)| response_epoch.parse::<u64>().ok())
            .is_some_and(|response_epoch| response_epoch < epoch)
        {
            Ok(ResponseIdDisposition::StaleEpoch)
        } else {
            Err(connector_transport_desynchronized_error(format!(
                "response id {actual_id} did not match request id \"{expected_id}\""
            )))
        }
    }

    async fn request(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> std::io::Result<serde_json::Value> {
        self.request_with_timeout(method, params, CONNECTOR_RPC_IO_TIMEOUT)
            .await
    }

    async fn request_with_timeout(
        &mut self,
        method: &str,
        params: serde_json::Value,
        io_timeout: Duration,
    ) -> std::io::Result<serde_json::Value> {
        if self.poisoned {
            return Err(connector_transport_poisoned_error());
        }

        let request_epoch = self.epoch;
        let expected_id = self.next_request_id();
        let request = json!({
            "jsonrpc": "2.0",
            "id": expected_id,
            "method": method,
            "params": params,
        });

        if let Err(err) = self.send_json(&request, io_timeout).await {
            self.poisoned = true;
            return Err(err);
        }

        let started_at = std::time::Instant::now();
        loop {
            let remaining = io_timeout.saturating_sub(started_at.elapsed());
            if remaining.is_zero() {
                self.epoch = self.epoch.saturating_add(1);
                return Err(connector_io_timeout_error("stdout read", io_timeout));
            }

            let response = match self.read_json(remaining).await {
                Ok(response) => response,
                Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
                    self.epoch = self.epoch.saturating_add(1);
                    return Err(connector_io_timeout_error("stdout read", io_timeout));
                }
                Err(err) => {
                    self.poisoned = true;
                    return Err(err);
                }
            };

            match Self::validate_response_id(&expected_id, request_epoch, &response) {
                Ok(ResponseIdDisposition::Matched) => return Ok(response),
                Ok(ResponseIdDisposition::StaleEpoch) => {
                    tracing::warn!(
                        expected_request_id = %expected_id,
                        actual_response_id = ?response.get("id"),
                        request_epoch,
                        "discarding late connector RPC response from an earlier timed-out epoch"
                    );
                }
                Err(err) => {
                    self.poisoned = true;
                    return Err(err);
                }
            }
        }
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

fn hyper_executor() -> HyperExecutor {
    HyperExecutor::with_spawn_fn(|future| {
        task::spawn_detached(future);
    })
}

fn spawn_http_connection<IO>(io: IO, app: Router)
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let tower_service = app.map_request(|request: hyper::Request<Incoming>| request.map(Body::new));
    let hyper_service = TowerToHyperService::new(tower_service);

    task::spawn_detached(async move {
        let mut builder = HyperConnectionBuilder::new(hyper_executor());
        builder.http2().enable_connect_protocol();

        let mut connection = pin!(builder.serve_connection_with_upgrades(io, hyper_service));
        if let Err(err) = connection.as_mut().await {
            tracing::debug!(error = %err, "failed to serve connection");
        }
    });
}

async fn serve_tcp(
    listener: TcpListener,
    app: Router,
    mut shutdown_rx: fcp_async_core::channel::watch::Receiver<bool>,
) -> HostResult<()> {
    loop {
        let accept = listener.accept();
        let shutdown = shutdown_rx.changed();
        let mut accept = pin!(accept);
        let mut shutdown = pin!(shutdown);
        match futures_util::future::select(accept.as_mut(), shutdown.as_mut()).await {
            futures_util::future::Either::Left((result, _)) => match result {
                Ok((stream, addr)) => {
                    tracing::debug!(transport = "tcp", remote_addr = %addr, "accepted connection");
                    spawn_http_connection(HyperIo::new(stream), app.clone());
                }
                Err(err) => handle_accept_error(err).await,
            },
            futures_util::future::Either::Right(_) => {
                tracing::info!(
                    event = "shutdown_signal",
                    transport = "tcp",
                    "stopping accept loop"
                );
                break;
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn serve_unix(
    listener: UnixListener,
    app: Router,
    mut shutdown_rx: fcp_async_core::channel::watch::Receiver<bool>,
) -> HostResult<()> {
    loop {
        let accept = listener.accept();
        let shutdown = shutdown_rx.changed();
        let mut accept = pin!(accept);
        let mut shutdown = pin!(shutdown);
        match futures_util::future::select(accept.as_mut(), shutdown.as_mut()).await {
            futures_util::future::Either::Left((result, _)) => match result {
                Ok((stream, addr)) => {
                    tracing::debug!(transport = "unix", remote_addr = ?addr, "accepted connection");
                    spawn_http_connection(HyperIo::new(stream), app.clone());
                }
                Err(err) => handle_accept_error(err).await,
            },
            futures_util::future::Either::Right(_) => {
                tracing::info!(
                    event = "shutdown_signal",
                    transport = "unix",
                    "stopping accept loop"
                );
                break;
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct AppState {
    registry: Arc<SubprocessRegistry>,
    doctor: DoctorService<SubprocessRegistry>,
    budget: Arc<BudgetPolicyEngine>,
    discovery: Arc<DiscoveryEndpoint<SubprocessRegistry, BudgetPolicyEngine>>,
    cancellation: Arc<CancellationController>,
    lifecycle: Arc<HostAdminStateStore>,
    rollout: Arc<RolloutController<SubprocessRegistry, HostAdminStateStore>>,
    supply_chain: Arc<SupplyChainGate>,
    capability_verifying_key: Option<Ed25519VerifyingKey>,
    revocation_cascade: Arc<RevocationCascadeVerifier>,
    hybrid_owner_verifier: Option<Arc<HybridOwnerProductionVerifier>>,
    approval_verifying_key: Option<Ed25519VerifyingKey>,
    admin_bearer_token: Option<Arc<str>>,
    connectors_file: Option<PathBuf>,
    /// Per-zone policy override map (br-flywheel_connectors-d4cij).
    ///
    /// `verify_live_request` looks the request's zone up here before
    /// invoking `simulate_policy_decision`. Missing entries fail closed so
    /// live preflight cannot bypass deny rules under an implicit empty policy.
    ///
    /// Entries are populated either at startup from
    /// `FCP_HOST_ZONE_POLICIES_FILE` (a JSON map keyed by ZoneId string)
    /// or via a future admin endpoint. Loading is intentionally separate
    /// from connector inventory so a connector-config rollout cannot
    /// accidentally drop policy state.
    zone_policies: Arc<RwLock<HashMap<ZoneId, ZonePolicyObject>>>,
    /// Per-zone hash-linked invoke audit chain (br-mvax3).
    ///
    /// Appended at four phases of every `/rpc/invoke`: preflight allow,
    /// preflight deny, dispatch result, dispatch error. Makes the
    /// README `every operation produces an audit event` claim
    /// literally true even when the connector returns no `receipt_id`
    /// or fails before producing a receipt.
    invoke_audit: Arc<fcp_host::InvokeAuditChain>,
    started_at: Instant,
}

impl AppState {
    /// Resolve the zone policy object for a request.
    ///
    /// Returns the configured policy when one is registered for `zone_id`,
    /// otherwise fails closed so live preflight cannot bypass deny rules.
    async fn lookup_zone_policy(&self, zone_id: &ZoneId) -> HostResult<ZonePolicyObject> {
        let policies = self.zone_policies.read().await;
        if let Some(policy) = policies.get(zone_id) {
            return Ok(policy.clone());
        }
        drop(policies);
        tracing::error!(
            zone_id = %zone_id.as_str(),
            event = "zone_policy_missing",
            "no zone policy configured for zone; denying live request",
        );
        Err(HostError::PreflightFailed(format!(
            "no zone policy configured for live request zone `{}`",
            zone_id.as_str()
        )))
    }
}

#[derive(Debug, Clone)]
struct VerifiedLiveRequest {
    principal: String,
    approval_required: bool,
    safety_tier: SafetyTier,
}

fn parse_cli_action() -> HostResult<CliAction> {
    parse_cli_action_from_args(std::env::args_os())
}

fn parse_cli_action_from_args<I, S>(args: I) -> HostResult<CliAction>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let remaining = args.map(Into::into).collect::<Vec<_>>();

    match remaining.as_slice() {
        [] => Ok(CliAction::Run),
        [arg] if arg == OsStr::new("-h") || arg == OsStr::new("--help") => Ok(CliAction::PrintHelp),
        [arg] if arg == OsStr::new("-V") || arg == OsStr::new("--version") => {
            Ok(CliAction::PrintVersion)
        }
        _ => {
            let rendered = remaining
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" ");
            Err(HostError::InvalidFilter(format!(
                "unexpected CLI arguments: {rendered}. fcp-host is configured via environment variables; use --help for supported startup controls"
            )))
        }
    }
}

fn print_cli_help() {
    println!(
        "\
fcp-host {}

Usage:
  fcp-host
  fcp-host --help
  fcp-host --version

Startup configuration is supplied via environment variables:
  FCP_HOST_BIND
  FCP_HOST_CONNECTORS or FCP_HOST_CONNECTORS_FILE
  FCP_HOST_LIFECYCLE_STATE_FILE
  FCP_HOST_ADMIN_BEARER_TOKEN
  FCP_HOST_CAPABILITY_PUBLIC_KEY or FCP_HOST_CAPABILITY_PUBLIC_KEY_FILE
  FCP_HOST_APPROVAL_PUBLIC_KEY or FCP_HOST_APPROVAL_PUBLIC_KEY_FILE
  FCP_HOST_HYBRID_OWNER_CONTEXT_FILE
  FCP_HOST_SELF_CHECK_TIMEOUT_MS
  FCP_HOST_SUPPLY_CHAIN_*
  FCP_HOST_HRW_LEASE_LOCAL_NODE
  FCP_HOST_HRW_LEASE_NODES
",
        env!("CARGO_PKG_VERSION")
    );
}

fn read_optional_env_string(name: &str) -> HostResult<Option<String>> {
    read_optional_env_string_from_result(name, std::env::var(name))
}

fn read_optional_env_string_from_result(
    name: &str,
    value: Result<String, std::env::VarError>,
) -> HostResult<Option<String>> {
    match value {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(HostError::InvalidFilter(format!(
            "{name} contains non-unicode data"
        ))),
    }
}

fn read_optional_trimmed_env_string(name: &str) -> HostResult<Option<String>> {
    read_optional_trimmed_env_string_from_result(name, std::env::var(name))
}

fn read_optional_trimmed_env_string_from_result(
    name: &str,
    value: Result<String, std::env::VarError>,
) -> HostResult<Option<String>> {
    Ok(
        read_optional_env_string_from_result(name, value)?.and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }),
    )
}

fn resolve_admin_bearer_token() -> HostResult<Option<Arc<str>>> {
    Ok(read_optional_trimmed_env_string("FCP_HOST_ADMIN_BEARER_TOKEN")?.map(Arc::<str>::from))
}

/// HTTP header name for binding the caller's asserted principal to the
/// capability token's subject/principal_id claim.
///
/// When present, the value is forwarded as `principal_override` to
/// [`evaluate_live_preflight`]; [`verify_live_request`] rejects the
/// request if the header value does not match the token's principal.
/// When absent, the capability-based identity model applies — the
/// token IS the principal (br-flywheel_connectors-t623k).
const PRINCIPAL_HEADER: &str = "x-principal";
const ADMIN_ZONE_HEADER: &str = "x-fcp-zone";

/// Extract the caller's asserted principal from the `X-Principal` header.
///
/// Returns `None` when the header is absent, non-UTF-8, or trimmed to
/// empty — all treated as "caller did not assert a principal, rely on
/// the token alone."
fn extract_principal_header(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(PRINCIPAL_HEADER)?.to_str().ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn extract_admin_zone_header(headers: &HeaderMap) -> HostResult<ZoneId> {
    let raw = headers
        .get(ADMIN_ZONE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            HostError::PreflightFailed(format!(
                "missing or invalid {ADMIN_ZONE_HEADER} header for admin API"
            ))
        })?;

    raw.parse().map_err(|error| {
        HostError::PreflightFailed(format!(
            "invalid {ADMIN_ZONE_HEADER} header for admin API: {error}"
        ))
    })
}

fn validate_admin_authorization(state: &AppState, headers: &HeaderMap) -> HostResult<()> {
    let expected = state.admin_bearer_token.as_deref().ok_or_else(|| {
        HostError::Unavailable(
            "admin API requires FCP_HOST_ADMIN_BEARER_TOKEN to be configured".to_string(),
        )
    })?;
    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let mut parts = value.split_ascii_whitespace();
            let scheme = parts.next()?;
            let token = parts.next()?;
            if parts.next().is_some() || !scheme.eq_ignore_ascii_case("Bearer") {
                return None;
            }
            Some(token)
        })
        .ok_or_else(|| {
            HostError::PreflightFailed(
                "missing or invalid Authorization header for admin API".to_string(),
            )
        })?;

    // Constant-time compare so a network attacker cannot learn the admin
    // bearer token byte-by-byte by measuring reject latency. `ct_eq` on
    // length-mismatched inputs still runs in time proportional to the
    // shorter input, which is acceptable here — the token length is not
    // itself the secret.
    if !bool::from(provided.as_bytes().ct_eq(expected.as_bytes())) {
        return Err(HostError::PreflightFailed(
            "admin bearer token rejected".to_string(),
        ));
    }

    let asserted_zone = extract_admin_zone_header(headers)?;
    if asserted_zone != ZoneId::owner() {
        return Err(HostError::PreflightFailed(format!(
            "admin API requires {ADMIN_ZONE_HEADER}: {}",
            ZoneId::owner().as_str()
        )));
    }
    Ok(())
}

async fn admin_auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    validate_admin_authorization(state.as_ref(), request.headers()).map_err(map_host_error)?;
    Ok(next.run(request).await)
}

fn parse_public_key_str(raw: &str, source: &str) -> HostResult<Option<Ed25519VerifyingKey>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let bytes = hex::decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .map_err(|error| {
            HostError::InvalidFilter(format!(
                "{source} must be hex or base64 encoded Ed25519 public key material: {error}"
            ))
        })?;
    parse_public_key_bytes(&bytes, source)
}

fn parse_public_key_bytes(bytes: &[u8], source: &str) -> HostResult<Option<Ed25519VerifyingKey>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != PUBLIC_KEY_SIZE {
        return Err(HostError::InvalidFilter(format!(
            "{source} must be {PUBLIC_KEY_SIZE} bytes, got {}",
            bytes.len()
        )));
    }

    let mut raw = [0u8; PUBLIC_KEY_SIZE];
    raw.copy_from_slice(bytes);
    Ed25519VerifyingKey::from_bytes(&raw)
        .map(Some)
        .map_err(|error| {
            HostError::InvalidFilter(format!("invalid Ed25519 public key in {source}: {error}"))
        })
}

fn resolve_verifying_key(
    inline_env: &str,
    file_env: &str,
) -> HostResult<Option<Ed25519VerifyingKey>> {
    let inline = read_optional_trimmed_env_string(inline_env)?;
    let file = read_optional_trimmed_env_string(file_env)?;

    resolve_verifying_key_from_sources(inline_env, inline, file_env, file)
}

fn resolve_verifying_key_from_sources(
    inline_env: &str,
    inline: Option<String>,
    file_env: &str,
    file: Option<String>,
) -> HostResult<Option<Ed25519VerifyingKey>> {
    if inline.is_some() && file.is_some() {
        return Err(HostError::InvalidFilter(format!(
            "set either {inline_env} or {file_env}, not both"
        )));
    }

    if let Some(raw) = inline {
        return parse_public_key_str(&raw, inline_env);
    }
    if let Some(path) = file {
        let bytes = std::fs::read(&path).map_err(|error| {
            HostError::InvalidFilter(format!("failed to read {file_env}='{path}': {error}"))
        })?;
        if let Ok(text) = std::str::from_utf8(&bytes)
            && let Ok(parsed) = parse_public_key_str(text, file_env)
        {
            return Ok(parsed);
        }
        return parse_public_key_bytes(&bytes, file_env);
    }

    Ok(None)
}

#[cfg(test)]
fn host_runtime_policy(zone_id: ZoneId) -> ZonePolicyObject {
    ZonePolicyObject {
        header: ObjectHeader {
            schema: fcp_cbor::SchemaId::new(
                "fcp.core",
                "ZonePolicyObject",
                semver::Version::new(1, 0, 0),
            ),
            zone_id: zone_id.clone(),
            created_at: u64::try_from(Utc::now().timestamp()).unwrap_or(0),
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        },
        zone_id,
        principal_allow: Vec::new(),
        principal_deny: Vec::new(),
        connector_allow: Vec::new(),
        connector_deny: Vec::new(),
        capability_allow: Vec::new(),
        capability_deny: Vec::new(),
        capability_ceiling: Vec::new(),
        transport_policy: ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        },
        decision_receipts: DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

fn invoke_request_from_preflight(request: &HostPreflightRequest) -> HostResult<InvokeRequest> {
    let capability_token = request.capability_token.clone().ok_or_else(|| {
        HostError::PreflightFailed("capability token is required for live preflight".to_string())
    })?;
    let zone_id = request.zone_id.clone().ok_or_else(|| {
        HostError::PreflightFailed("zone_id is required for live preflight".to_string())
    })?;
    let operation = request.operation.parse().map_err(|error| {
        HostError::InvalidFilter(format!(
            "invalid preflight operation '{}': {error}",
            request.operation
        ))
    })?;

    Ok(InvokeRequest {
        r#type: "invoke".to_owned(),
        id: request.request_id.clone(),
        connector_id: request.connector_id.clone(),
        operation,
        zone_id,
        input: request.params.clone().unwrap_or(serde_json::Value::Null),
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: request.approval_tokens.clone(),
    })
}

fn simulate_request_from_host(request: &HostSimulateRequest) -> HostResult<SimulateRequest> {
    let capability_token = request.capability_token.clone().ok_or_else(|| {
        HostError::PreflightFailed("capability token is required for live simulate".to_string())
    })?;
    let connector_id = request.connector_id.parse().map_err(|error| {
        HostError::InvalidFilter(format!(
            "invalid simulate connector id '{}': {error}",
            request.connector_id
        ))
    })?;
    let zone_raw = request.zone_id.as_deref().ok_or_else(|| {
        HostError::PreflightFailed("zone_id is required for live simulate".to_string())
    })?;
    let zone_id = zone_raw.parse().map_err(|error| {
        HostError::InvalidFilter(format!("invalid simulate zone_id '{zone_raw}': {error}"))
    })?;
    let operation = request.operation.parse().map_err(|error| {
        HostError::InvalidFilter(format!(
            "invalid simulate operation '{}': {error}",
            request.operation
        ))
    })?;

    Ok(SimulateRequest {
        r#type: "simulate".to_owned(),
        id: RequestId::new(request.request_id.clone()),
        connector_id,
        operation,
        zone_id,
        input: request.input.clone().unwrap_or(serde_json::Value::Null),
        capability_token,
        estimate_cost: request.estimate_cost,
        check_availability: request.check_availability,
        context: None,
        correlation_id: None,
    })
}

fn invoke_request_from_simulate(request: &HostSimulateRequest) -> HostResult<InvokeRequest> {
    let simulate_request = simulate_request_from_host(request)?;
    Ok(InvokeRequest {
        r#type: "invoke".to_owned(),
        id: simulate_request.id.clone(),
        connector_id: simulate_request.connector_id.clone(),
        operation: simulate_request.operation.clone(),
        zone_id: simulate_request.zone_id.clone(),
        input: simulate_request.input.clone(),
        capability_token: simulate_request.capability_token.clone(),
        holder_proof: None,
        context: simulate_request.context.clone(),
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: Some(request.deadline_ms),
        correlation_id: simulate_request.correlation_id.clone(),
        provenance: None,
        approval_tokens: request.approval_tokens.clone(),
    })
}

fn map_simulate_cost_confidence(confidence: CostEstimateConfidence) -> SimulateCostConfidence {
    match confidence {
        CostEstimateConfidence::Low => SimulateCostConfidence::Low,
        CostEstimateConfidence::Medium => SimulateCostConfidence::Medium,
        CostEstimateConfidence::High => SimulateCostConfidence::High,
    }
}

fn map_simulate_cost_estimate(estimate: fcp_core::CostEstimate) -> SimulateCostEstimate {
    SimulateCostEstimate {
        api_credits: estimate.api_credits,
        estimated_duration_ms: estimate.estimated_duration_ms,
        estimated_bytes: estimate.estimated_bytes,
        confidence: estimate.confidence.map(map_simulate_cost_confidence),
    }
}

fn map_simulate_resource_availability(
    availability: ResourceAvailability,
) -> SimulateResourceAvailability {
    SimulateResourceAvailability {
        available: availability.available,
        rate_limit_remaining: availability.rate_limit_remaining,
        rate_limit_reset_at: availability.rate_limit_reset_at,
        details: availability.details,
    }
}

fn simulate_receipt_for_request(
    request: &HostSimulateRequest,
    input: &serde_json::Value,
    phase: SimulatePhase,
    would_succeed: bool,
    duration_ms: u64,
) -> HostResult<SimulateReceipt> {
    Ok(SimulateReceipt {
        receipt_id: format!("sim_{}", RequestId::random()),
        connector_id: request.connector_id.clone(),
        operation: request.operation.clone(),
        phase,
        would_succeed,
        input_digest: Some(hex::encode(request_input_hash(input)?)),
        duration_ms,
        simulated_at: Utc::now(),
    })
}

async fn record_simulate_receipt_summary(
    lifecycle: &HostAdminStateStore,
    receipt: &SimulateReceipt,
) {
    if let Err(err) = lifecycle.record_simulate_receipt(receipt.clone()).await {
        tracing::warn!(
            event = "simulate_receipt_persist_error",
            connector_id = %receipt.connector_id,
            operation = %receipt.operation,
            receipt_id = %receipt.receipt_id,
            error = %err,
            "failed to persist simulate receipt"
        );
    }
}

fn is_simulate_unsupported(error: &HostError) -> bool {
    matches!(
        error,
        HostError::RegistryError(message)
            if message.contains("Unknown method: simulate")
                || message.contains("does not support simulation")
                || message.contains("unsupported")
    )
}

fn request_input_hash(input: &serde_json::Value) -> HostResult<[u8; 32]> {
    let bytes = to_deterministic_cbor(input).map_err(|error| {
        HostError::Internal(format!("failed to canonicalize input payload: {error}"))
    })?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn approval_token_signing_bytes(token: &ApprovalToken) -> HostResult<Vec<u8>> {
    let mut unsigned = token.clone();
    unsigned.signature = None;
    fcp_cbor::to_canonical_cbor(&unsigned).map_err(|error| {
        HostError::Internal(format!("failed to canonicalize approval token: {error}"))
    })
}

fn verify_approval_tokens(
    tokens: &[ApprovalToken],
    verifying_key: Option<&Ed25519VerifyingKey>,
) -> HostResult<()> {
    if tokens.is_empty() {
        return Ok(());
    }
    let key = verifying_key.ok_or_else(|| {
        HostError::PreflightFailed(
            "approval tokens were supplied, but FCP_HOST_APPROVAL_PUBLIC_KEY[_FILE] is not configured"
                .to_string(),
        )
    })?;

    for token in tokens {
        let signature = token.signature.as_ref().ok_or_else(|| {
            HostError::PreflightFailed(format!(
                "approval token `{}` is unsigned and cannot be verified",
                token.token_id
            ))
        })?;
        let signature = Ed25519Signature::try_from_slice(signature).map_err(|error| {
            HostError::PreflightFailed(format!(
                "approval token `{}` has an invalid signature: {error}",
                token.token_id
            ))
        })?;
        let bytes = approval_token_signing_bytes(token)?;
        key.verify(&bytes, &signature).map_err(|error| {
            HostError::PreflightFailed(format!(
                "approval token `{}` failed signature verification: {error}",
                token.token_id
            ))
        })?;
    }

    Ok(())
}

fn claims_principal(claims: &fcp_crypto::cose::CwtClaims) -> Option<&str> {
    claims
        .get_subject()
        .or_else(|| match claims.get(fcp2_claims::PRINCIPAL_ID) {
            Some(ciborium::Value::Text(principal)) => Some(principal.as_str()),
            _ => None,
        })
}

fn capability_token_b64(token: &fcp_core::CapabilityToken) -> HostResult<String> {
    let bytes = token.raw().to_cbor().map_err(|error| {
        HostError::Internal(format!(
            "failed to serialize capability token for verification: {error}"
        ))
    })?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn object_id_from_token_id_bytes(token_id: &[u8]) -> ObjectId {
    if token_id.len() == 32 {
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(token_id);
        ObjectId::from_bytes(bytes)
    } else {
        ObjectId::from_unscoped_bytes(token_id)
    }
}

fn revocation_cascade_token_id(
    token: &fcp_core::CapabilityToken,
    claims: &fcp_crypto::cose::CwtClaims,
) -> HostResult<ObjectId> {
    if let Some(token_id) = claims.get_jti() {
        return Ok(object_id_from_token_id_bytes(token_id));
    }

    let bytes = token.raw().to_cbor().map_err(|error| {
        HostError::PreflightFailed(format!(
            "revocation cascade could not derive a token id from the capability token: {error}"
        ))
    })?;
    Ok(ObjectId::from_unscoped_bytes(&bytes))
}

fn revocation_cascade_issuer_kid(token: &fcp_core::CapabilityToken) -> HostResult<KeyId> {
    let kid = token.raw().get_key_id().map_err(|error| {
        HostError::PreflightFailed(format!(
            "revocation cascade could not read the token issuer KID: {error}"
        ))
    })?;
    KeyId::try_from_slice(&kid).map_err(|error| {
        HostError::PreflightFailed(format!(
            "revocation cascade rejected token issuer KID: {error}"
        ))
    })
}

fn verify_live_revocation_cascade(
    state: &AppState,
    token: &fcp_core::CapabilityToken,
    claims: &fcp_crypto::cose::CwtClaims,
) -> HostResult<()> {
    let token_id = revocation_cascade_token_id(token, claims)?;
    let issuer_kid = revocation_cascade_issuer_kid(token)?;
    state
        .revocation_cascade
        .verify(token_id, issuer_kid)
        .map_err(|error| {
            HostError::PreflightFailed(format!(
                "capability token rejected by revocation cascade: {error}"
            ))
        })?;
    Ok(())
}

fn decode_hybrid_owner_invoke_evidence(raw: &str) -> HostResult<HybridOwnerInvokeEvidence> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|error| {
            HostError::PreflightFailed(format!(
                "hybrid owner evidence tag is not valid base64 CBOR: {error}"
            ))
        })?;
    ciborium::from_reader(bytes.as_slice()).map_err(|error| {
        HostError::PreflightFailed(format!(
            "hybrid owner evidence tag is not a valid evidence envelope: {error}"
        ))
    })
}

fn hybrid_owner_invoke_evidence(
    request: &InvokeRequest,
) -> HostResult<Option<HybridOwnerInvokeEvidence>> {
    let Some(raw) = request
        .context
        .as_ref()
        .and_then(|context| context.request_tags.get(HYBRID_OWNER_EVIDENCE_TAG))
    else {
        return Ok(None);
    };
    decode_hybrid_owner_invoke_evidence(raw).map(Some)
}

fn verify_live_hybrid_owner_capability(
    state: &AppState,
    request: &InvokeRequest,
) -> HostResult<()> {
    // br-jhbk1: when the host is NOT configured with a hybrid-owner
    // verifier (FCP_HOST_HYBRID_OWNER_CONTEXT_FILE unset) AND the
    // request carries the hybrid-owner evidence tag, the caller is
    // explicitly asking for V4 hybrid-owner verification. The host
    // cannot honor that intent without a verifier, so fail CLOSED
    // rather than silently letting the request through. The pre-fix
    // behavior of returning Ok(()) here regardless of whether the
    // request claimed hybrid-owner governance was an auth-bypass-via-
    // missing-config: an operator who forgot to set the env var
    // silently accepted ALL invokes — including ones that should
    // require post-quantum V3-to-V4 migration verification. See
    // docs/audit/security-audit-saas-alpha-2026-05-02.md §a.
    //
    // Tokens that do NOT carry the evidence tag continue to take the
    // legacy V3-only path (no verifier needed) for back-compat.
    let Some(verifier) = state.hybrid_owner_verifier.as_deref() else {
        if hybrid_owner_invoke_evidence(request)?.is_some() {
            return Err(HostError::PreflightFailed(format!(
                "request carries hybrid-owner evidence tag `{HYBRID_OWNER_EVIDENCE_TAG}` \
                 but this host is not configured for hybrid-owner verification \
                 (set {HYBRID_OWNER_CONTEXT_FILE_ENV} to enable; br-jhbk1)"
            )));
        }
        return Ok(());
    };
    let evidence = hybrid_owner_invoke_evidence(request)?.ok_or_else(|| {
        HostError::PreflightFailed(format!(
            "missing hybrid owner evidence tag `{HYBRID_OWNER_EVIDENCE_TAG}` for owner-governed capability token"
        ))
    })?;
    verifier.verify_capability_token(&request.zone_id, &request.capability_token, &evidence)
}

fn capability_constraints_from_claims(
    claims: &fcp_crypto::cose::CwtClaims,
) -> HostResult<CapabilityConstraints> {
    let Some(encoded_constraints) = claims.get(fcp2_claims::CONSTRAINTS) else {
        return Err(HostError::PreflightFailed(
            "capability token is missing constraints required for live execution".to_string(),
        ));
    };

    let mut bytes = Vec::new();
    ciborium::into_writer(encoded_constraints, &mut bytes).map_err(|error| {
        HostError::PreflightFailed(format!(
            "failed to reserialize capability constraints claim: {error}"
        ))
    })?;
    ciborium::from_reader(&bytes[..]).map_err(|error| {
        HostError::PreflightFailed(format!(
            "failed to decode capability constraints claim: {error}"
        ))
    })
}

fn live_constraint_resource_uri(input: &Value) -> Option<String> {
    ["resource_uri", "resource", "uri", "url"]
        .iter()
        .find_map(|key| {
            input
                .get(*key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
}

fn enforce_live_capability_constraints(
    request: &InvokeRequest,
    claims: &fcp_crypto::cose::CwtClaims,
    principal: &str,
    resource_uri: Option<&str>,
) -> HostResult<()> {
    let constraints = capability_constraints_from_claims(claims)?;
    let input_cbor = to_deterministic_cbor(&request.input).map_err(|error| {
        HostError::PreflightFailed(format!(
            "failed to canonicalize request input for capability constraints: {error}"
        ))
    })?;
    let requested_at_unix_ms = u64::try_from(Utc::now().timestamp_millis()).map_err(|_| {
        HostError::PreflightFailed(
            "system clock produced a negative timestamp for capability constraint enforcement"
                .to_string(),
        )
    })?;
    let principal = PrincipalId::new(principal).map_err(|error| {
        HostError::PreflightFailed(format!(
            "capability token principal is not canonical for constraint enforcement: {error}"
        ))
    })?;

    let descriptor = RequestDescriptor {
        object_id: ObjectId::from_unscoped_bytes(request.id.0.as_bytes()),
        operation: request.operation.clone(),
        principal,
        host: String::new(),
        resource_uri: resource_uri.unwrap_or_default().to_string(),
        requested_at_unix_ms,
        observed_calls: 1,
        observed_bytes: input_cbor.len().try_into().unwrap_or(u64::MAX),
    };

    match DefaultConstraintEnforcer::new().evaluate(&constraints, &descriptor) {
        ConstraintEvaluation::Allow => Ok(()),
        ConstraintEvaluation::Deny(reason) => {
            let audit_descriptor = capability_constraint_audit_descriptor(
                request.id.0.as_str(),
                request.connector_id.as_str(),
                request.operation.as_str(),
                request.zone_id.as_str(),
                &descriptor,
            );
            emit_capability_constraint_denial_audit_event(
                &audit_descriptor,
                &reason.kind,
                "fcp-host.live",
            );

            Err(HostError::PreflightFailed(format!(
                "capability constraint denied during live execution ({:?}): {}",
                reason.kind, reason.explanation
            )))
        }
    }
}

const DEPLOYMENT_TIER_DENIED_AUDIT_EVENT_TYPE: &str = "deployment_tier.denied";

fn current_deployment_classification() -> DeploymentClassification {
    // The host binary does not yet have live mesh quorum signals wired into
    // AppState. Classify the production boundary as single-host Evaluation so
    // Risky/Dangerous dispatch fails closed until those signals exist.
    classify_deployment_mode(MeshQuorumSignals::single_host_evaluation())
}

fn select_host_operational_model_from_env_values(
    classification: &DeploymentClassification,
    default_env: Option<&str>,
    accept_degraded_env: Option<&str>,
) -> OperationalModelSelection {
    select_operational_model_from_env_for_deployment(
        default_env,
        accept_degraded_env,
        classification.signals.healthy_peer_count == 0,
    )
}

fn current_operational_model_selection(
    classification: &DeploymentClassification,
) -> HostResult<OperationalModelSelection> {
    let default_env = read_optional_trimmed_env_string(TRUTH_PRECEDENCE_DEFAULT_ENV)?;
    let accept_degraded_env =
        read_optional_trimmed_env_string(TRUTH_PRECEDENCE_ACCEPT_DEGRADED_SINGLE_HOST_ENV)?;
    Ok(select_host_operational_model_from_env_values(
        classification,
        default_env.as_deref(),
        accept_degraded_env.as_deref(),
    ))
}

fn emit_operational_model_selection_log(selection: &OperationalModelSelection) {
    if let Some(warning) = selection.warning {
        tracing::warn!(
            target: "fcp_host::deployment_mode",
            event = "single_host_v2_fallback",
            requested_model = selection.requested.label(),
            effective_model = selection.effective.label(),
            single_host_detected = selection.single_host_detected,
            degraded_v2_opt_in = selection.degraded_v2_opt_in,
            "{warning}"
        );
    } else if selection.degraded_v2_opt_in {
        tracing::warn!(
            target: "fcp_host::deployment_mode",
            event = "single_host_v2_degraded_opt_in",
            requested_model = selection.requested.label(),
            effective_model = selection.effective.label(),
            single_host_detected = selection.single_host_detected,
            degraded_v2_opt_in = selection.degraded_v2_opt_in,
            "V2MeshNative degraded single-host mode accepted by explicit operator opt-in"
        );
    } else {
        tracing::info!(
            target: "fcp_host::deployment_mode",
            event = "operational_model_selection",
            requested_model = selection.requested.label(),
            effective_model = selection.effective.label(),
            single_host_detected = selection.single_host_detected,
            degraded_v2_opt_in = selection.degraded_v2_opt_in,
            "fcp-host operational model selected"
        );
    }
}

fn deployment_tier_refusal_reason_code(refusal: &DeploymentTierRefusal) -> &'static str {
    match refusal {
        DeploymentTierRefusal::TierRequiresMeshActive { .. } => "TIER_REQUIRES_MESH_ACTIVE",
        DeploymentTierRefusal::TierForbidden { .. } => "TIER_FORBIDDEN",
    }
}

fn deployment_tier_refusal_payload(refusal: &DeploymentTierRefusal) -> String {
    serde_json::to_string(refusal).unwrap_or_else(|error| {
        format!("{{\"kind\":\"serialization_error\",\"message\":\"{error}\"}}")
    })
}

fn deployment_tier_refusal_message(refusal: &DeploymentTierRefusal) -> String {
    format!(
        "deployment tier admission denied: {}",
        deployment_tier_refusal_payload(refusal)
    )
}

fn emit_deployment_tier_denial_audit_event(
    request: &InvokeRequest,
    tier: SafetyTier,
    classification: &DeploymentClassification,
    refusal: &DeploymentTierRefusal,
) {
    let lease_coordinator = match classification.signals.lease_coordinator_reachable {
        None => "n/a",
        Some(true) => "reachable",
        Some(false) => "unreachable",
    };
    let refusal_payload = deployment_tier_refusal_payload(refusal);
    tracing::warn!(
        audit_event_type = DEPLOYMENT_TIER_DENIED_AUDIT_EVENT_TYPE,
        reason_code = deployment_tier_refusal_reason_code(refusal),
        refusal = %refusal_payload,
        safety_tier = ?tier,
        deployment_mode = classification.mode.label(),
        deployment_reason = classification.reason.label(),
        healthy_peer_count = classification.signals.healthy_peer_count,
        lease_coordinator,
        revocation_fresh = classification.signals.revocation_snapshot_fresh,
        request_id = request.id.0.as_str(),
        connector_id = request.connector_id.as_str(),
        operation = request.operation.as_str(),
        zone_id = request.zone_id.as_str(),
        "deployment_tier_denied_audit_event"
    );
}

const HRW_LEASE_LOCAL_NODE_ENV: &str = "FCP_HOST_HRW_LEASE_LOCAL_NODE";
const HRW_LEASE_NODES_ENV: &str = "FCP_HOST_HRW_LEASE_NODES";

#[derive(Debug, Clone, PartialEq, Eq)]
struct HrwLeaseRoutingConfig {
    local_node: TailscaleNodeId,
    eligible_nodes: Vec<TailscaleNodeId>,
}

#[cfg(test)]
static TEST_HRW_LEASE_ROUTING_OVERRIDE: std::sync::Mutex<Option<Option<HrwLeaseRoutingConfig>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
struct TestHrwLeaseRoutingOverrideGuard;

#[cfg(test)]
impl Drop for TestHrwLeaseRoutingOverrideGuard {
    fn drop(&mut self) {
        *TEST_HRW_LEASE_ROUTING_OVERRIDE
            .lock()
            .expect("HRW lease routing override lock poisoned") = None;
    }
}

#[cfg(test)]
fn set_test_hrw_lease_routing_override(
    config: Option<HrwLeaseRoutingConfig>,
) -> TestHrwLeaseRoutingOverrideGuard {
    let mut guard = TEST_HRW_LEASE_ROUTING_OVERRIDE
        .lock()
        .expect("HRW lease routing override lock poisoned");
    assert!(guard.is_none(), "HRW lease routing override already set");
    *guard = Some(config);
    TestHrwLeaseRoutingOverrideGuard
}

fn parse_hrw_lease_node_id(raw: &str, env_name: &str) -> HostResult<TailscaleNodeId> {
    TailscaleNodeId::try_new(raw.to_owned()).map_err(|error| {
        HostError::InvalidFilter(format!("invalid {env_name} node id `{raw}`: {error}"))
    })
}

fn parse_hrw_lease_node_set(raw: &str, env_name: &str) -> HostResult<Vec<TailscaleNodeId>> {
    let mut seen = HashSet::new();
    let mut nodes = Vec::new();
    for raw_node in raw.split(',') {
        let trimmed = raw_node.trim();
        if trimmed.is_empty() {
            continue;
        }
        let node = parse_hrw_lease_node_id(trimmed, env_name)?;
        if seen.insert(node.as_str().to_owned()) {
            nodes.push(node);
        }
    }
    if nodes.is_empty() {
        return Err(HostError::InvalidFilter(format!(
            "{env_name} must list at least one node id"
        )));
    }
    Ok(nodes)
}

fn parse_hrw_lease_routing_config_from_env_values(
    local_node: Option<&str>,
    eligible_nodes: Option<&str>,
) -> HostResult<Option<HrwLeaseRoutingConfig>> {
    match (local_node, eligible_nodes) {
        (None, None) => Ok(None),
        (Some(local_node), Some(eligible_nodes)) => {
            let local_node = parse_hrw_lease_node_id(local_node, HRW_LEASE_LOCAL_NODE_ENV)?;
            let eligible_nodes = parse_hrw_lease_node_set(eligible_nodes, HRW_LEASE_NODES_ENV)?;
            if !eligible_nodes.iter().any(|node| node == &local_node) {
                return Err(HostError::InvalidFilter(format!(
                    "{HRW_LEASE_NODES_ENV} must include local node `{}`",
                    local_node.as_str()
                )));
            }
            Ok(Some(HrwLeaseRoutingConfig {
                local_node,
                eligible_nodes,
            }))
        }
        (Some(_), None) | (None, Some(_)) => Err(HostError::InvalidFilter(format!(
            "set both {HRW_LEASE_LOCAL_NODE_ENV} and {HRW_LEASE_NODES_ENV} to enable singleton_writer HRW lease routing"
        ))),
    }
}

fn current_hrw_lease_routing_config() -> HostResult<Option<HrwLeaseRoutingConfig>> {
    #[cfg(test)]
    {
        if let Some(config) = TEST_HRW_LEASE_ROUTING_OVERRIDE
            .lock()
            .expect("HRW lease routing override lock poisoned")
            .clone()
        {
            return Ok(config);
        }
    }

    let local_node = read_optional_trimmed_env_string(HRW_LEASE_LOCAL_NODE_ENV)?;
    let eligible_nodes = read_optional_trimmed_env_string(HRW_LEASE_NODES_ENV)?;
    parse_hrw_lease_routing_config_from_env_values(local_node.as_deref(), eligible_nodes.as_deref())
}

fn json_schema_declares_singleton_writer(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            let state_model = map
                .get("x-fcp-state-model")
                .or_else(|| map.get("x-fcp-state_model"))
                .or_else(|| map.get("state_model"))
                .and_then(Value::as_str);
            if state_model == Some("singleton_writer") {
                return true;
            }
            if map
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|properties| properties.contains_key("lease_seq"))
            {
                return true;
            }
            if map
                .get("required")
                .and_then(Value::as_array)
                .is_some_and(|required| {
                    required
                        .iter()
                        .any(|field| field.as_str() == Some("lease_seq"))
                })
            {
                return true;
            }
            map.values().any(json_schema_declares_singleton_writer)
        }
        Value::Array(values) => values.iter().any(json_schema_declares_singleton_writer),
        _ => false,
    }
}

fn operation_requires_hrw_lease(
    tool: &ToolDescriptor,
    request: &InvokeRequest,
    connector_declares_singleton_writer: bool,
) -> bool {
    connector_declares_singleton_writer
        || request.lease_seq.is_some()
        || json_schema_declares_singleton_writer(&tool.input_schema)
}

fn update_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn singleton_writer_lease_subject_id(request: &InvokeRequest) -> ObjectId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP-HOST-SINGLETON-WRITER-HRW-LEASE-V1");
    update_len_prefixed(&mut hasher, request.connector_id.as_str().as_bytes());
    update_len_prefixed(&mut hasher, request.operation.as_str().as_bytes());
    update_len_prefixed(&mut hasher, request.zone_id.as_str().as_bytes());
    ObjectId::from_bytes(*hasher.finalize().as_bytes())
}

fn hrw_lease_refusal_message(reason: &fcp_mesh::planner::LeaseTransferReason) -> String {
    let payload = serde_json::to_string(reason).unwrap_or_else(|error| {
        format!("{{\"reason\":\"serialization_error\",\"message\":\"{error}\"}}")
    });
    format!("HRW lease routing refused singleton_writer invoke: {payload}")
}

fn enforce_hrw_lease_route(
    request: &InvokeRequest,
    routing: Option<&HrwLeaseRoutingConfig>,
) -> HostResult<()> {
    let subject_id = singleton_writer_lease_subject_id(request);
    let Some(routing) = routing else {
        let reason = fcp_mesh::planner::LeaseTransferReason::NoEligibleHolder {
            zone_id: request.zone_id.clone(),
            subject_id,
            purpose: CoreLeasePurpose::ConnectorStateWrite,
        };
        return Err(HostError::PreflightFailed(hrw_lease_refusal_message(
            &reason,
        )));
    };

    fcp_mesh::planner::admit_lease_holder(
        &request.zone_id,
        &subject_id,
        CoreLeasePurpose::ConnectorStateWrite,
        &routing.eligible_nodes,
        &routing.local_node,
    )
    .map(|selection| {
        tracing::debug!(
            event = "hrw_lease_route_admitted",
            connector_id = %request.connector_id,
            operation = %request.operation,
            zone_id = %request.zone_id,
            subject_id = %selection.subject_id,
            holder = %selection.holder.as_str(),
            "singleton_writer invoke admitted by HRW lease routing"
        );
    })
    .map_err(|reason| {
        tracing::warn!(
            event = "hrw_lease_route_refused",
            connector_id = %request.connector_id,
            operation = %request.operation,
            zone_id = %request.zone_id,
            reason = ?reason,
            "singleton_writer invoke refused by HRW lease routing"
        );
        HostError::PreflightFailed(hrw_lease_refusal_message(&reason))
    })
}

fn enforce_live_deployment_tier(request: &InvokeRequest, tier: SafetyTier) -> HostResult<()> {
    let classification = current_deployment_classification();
    match admit_safety_tier(&classification, tier) {
        Ok(()) => Ok(()),
        Err(refusal) => {
            emit_deployment_tier_denial_audit_event(request, tier, &classification, &refusal);
            Err(HostError::PreflightFailed(deployment_tier_refusal_message(
                &refusal,
            )))
        }
    }
}

const HOST_STATE_MISSING_VERIFYING_KEY_REASON_PREFIX: &str =
    "No verifying key found for token key ID ";

fn authoritative_persisted_capability_rejection_reason(
    verify: &fcp_host::CapabilityTokenVerifyResponse,
    fallback: &'static str,
) -> Option<String> {
    verify
        .rejection_reasons
        .iter()
        .find(|reason| !reason.starts_with(HOST_STATE_MISSING_VERIFYING_KEY_REASON_PREFIX))
        .cloned()
        .or_else(|| (!verify.temporally_valid || !verify.scope_valid).then(|| fallback.to_string()))
}

const CANCEL_SELF_CONNECTOR_ID: &str = "fcp.host.cancel-self:test:1.0.0";
const CANCEL_SELF_CAPABILITY_ID: &str = "host.cancel-self";
const CANCEL_SELF_OPERATION_ID: &str = "host.cancel-self";

async fn verify_live_request(
    state: &AppState,
    request: &InvokeRequest,
    principal_override: Option<&str>,
) -> HostResult<VerifiedLiveRequest> {
    // Connector home-zone binding (br-flywheel_connectors-by4vu).
    //
    // Without this gate, a structurally-valid capability token signed for
    // zone Z lets the holder invoke ANY connector whose operations match
    // the token's `capability` claim — even connectors whose manifest pins
    // them to a different zone (e.g. a `home = z:work` connector reachable
    // from a `z:secure` request). The gateway never consulted any
    // connector-side zone declaration before this check.
    //
    // Enforcement is opt-in: when `allowed_zones` is empty (the default for
    // existing inventories), the gateway preserves pre-binding behavior.
    // Operators set the list per-connector to fail-closed against
    // unintended zones. The error path emits a distinct rejection message
    // so receipts and logs distinguish zone-binding violations from
    // generic preflight failures.
    // br-v2kt4: explicit fail-closed semantics for empty allowed_zones
    // when the operator opted in via enforce_empty_allow_lists. Default
    // (false) preserves the back-compat permissive path.
    //
    // br-l9tt6: snapshot ALL THREE allow-list fields under one registry
    // read-lock so the zone gate and the operation gate that follows
    // both decide against the SAME admin-state generation. The earlier
    // shape took two separate `state.read().await` acquisitions per
    // gate (allow-list, then `enforce_empty`), which let a concurrent
    // admin writer interleave between them and produce a
    // stale-allow-list + fresh-enforce-flag mix — a real fail-OPEN
    // window during in-flight config updates.
    let allow_snapshot = state
        .registry
        .allow_list_snapshot(&request.connector_id)
        .await;
    if let Some(snapshot) = &allow_snapshot {
        let allowed = &snapshot.allowed_zones;
        if allowed.is_empty() {
            if snapshot.enforce_empty_allow_lists {
                return Err(HostError::PreflightFailed(format!(
                    "connector `{}` has no `allowed_zones` and is configured \
                     enforce_empty_allow_lists=true; deny-all (br-v2kt4)",
                    request.connector_id
                )));
            }
            // empty + !enforce_empty -> back-compat permissive path
        } else if !allowed.iter().any(|zone| zone == request.zone_id.as_str()) {
            return Err(HostError::PreflightFailed(format!(
                "connector `{}` is not bound to zone `{}` (allowed: [{}])",
                request.connector_id,
                request.zone_id.as_str(),
                allowed.join(", ")
            )));
        }
    }

    // br-ike8x: operator-pinned operation gate. The pre-existing
    // operation check (against `introspection.tools` further down)
    // trusts the connector's runtime self-report — a malicious or
    // drifted connector binary that adds new operations under a
    // permissive `tool.capability` would pass that gate even if the
    // operator never approved those ops in the manifest. The
    // ConnectorManifestCheck in `crates/fcp-host/src/enforcement.rs`
    // was designed for exactly this purpose but was never wired
    // into the production invoke path. Mirror the `allowed_zones`
    // shape directly here: when the operator pins a non-empty
    // `allowed_operations` set on the ManagedConnectorConfig, the
    // host gateway rejects requests whose `operation` is not in it.
    // Empty preserves pre-pinning behavior for back-compat.
    // br-v2kt4: same explicit fail-closed shape for empty allowed_operations.
    // br-l9tt6: re-uses the snapshot captured above so both gates
    // decide against the same atomic read.
    if let Some(snapshot) = &allow_snapshot {
        let allowed_ops = &snapshot.allowed_operations;
        if allowed_ops.is_empty() {
            if snapshot.enforce_empty_allow_lists {
                return Err(HostError::PreflightFailed(format!(
                    "connector `{}` has no `allowed_operations` and is configured \
                     enforce_empty_allow_lists=true; deny-all (br-v2kt4)",
                    request.connector_id
                )));
            }
            // empty + !enforce_empty -> back-compat permissive path
        } else if !allowed_ops
            .iter()
            .any(|op| op == request.operation.as_str())
        {
            return Err(HostError::PreflightFailed(format!(
                "connector `{}` does not allow operation `{}` (allowed: [{}])",
                request.connector_id,
                request.operation.as_str(),
                allowed_ops.join(", ")
            )));
        }
    }

    let introspection = state.discovery.introspect(&request.connector_id).await?;
    let tool = introspection
        .tools
        .iter()
        .find(|tool| tool.name == request.operation.as_str())
        .ok_or_else(|| {
            HostError::InvalidFilter(format!(
                "connector `{}` does not expose operation `{}`",
                request.connector_id, request.operation
            ))
        })?;

    let capability_key = state.capability_verifying_key.as_ref().ok_or_else(|| {
        HostError::PreflightFailed(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY[_FILE] is not configured, so live auth checks cannot be verified"
                .to_string(),
        )
    })?;
    let constraint_resource_uri = live_constraint_resource_uri(&request.input);
    let constraint_resource_uris = constraint_resource_uri
        .iter()
        .cloned()
        .collect::<Vec<String>>();
    // The gateway has no link from a capability token back to the
    // specific SubprocessConnector instance that will ultimately
    // execute the operation — handshake uses `requested_instance_id:
    // None` and the connector chooses its own id, which the gateway
    // never captures. Passing a per-request random `InstanceId::new()`
    // here used to satisfy the verifier's signature while being the
    // worst of both worlds: tokens that declared an `instance_id`
    // claim were always rejected (the random UUID never matched),
    // while tokens that did NOT declare one passed without any
    // instance check. Use `without_instance_binding` to honestly say
    // "gateway can't enforce this; defer to the connector process"
    // (br-flywheel_connectors-5qp7o).
    let verifier = CapabilityVerifier::without_instance_binding(
        capability_key.to_bytes(),
        request.zone_id.clone(),
    );
    // br-jkcka.8: gateway vantage produces UnboundVerified. The connector
    // process (which knows its real InstanceId) is expected to re-verify
    // with CapabilityVerifier::new or promote_with_instance before
    // executing the operation. See docs/architecture/adr/jkcka-typestate-split.md.
    let verified_token = verifier
        .verify_unbound(
            request.capability_token.clone(),
            &tool.capability,
            &request.operation,
            &constraint_resource_uris,
        )
        .map_err(|error| {
            HostError::PreflightFailed(format!("capability token rejected: {error}"))
        })?;
    let verified_claims = verified_token.claims();

    // m8j0q.A.9 / br-yowdy: reject directly-revoked tokens and revoked
    // issuer-chain hops through the bounded fcp-evidence cascade walker before
    // the live request can proceed into holder proof or persisted token-state
    // validation.
    verify_live_revocation_cascade(state, &request.capability_token, verified_claims)?;
    verify_live_hybrid_owner_capability(state, request)?;

    enforce_live_deployment_tier(request, tool.safety_tier)?;

    let connector_declares_singleton_writer = state
        .registry
        .connector_requires_singleton_writer(&request.connector_id)
        .await;
    if operation_requires_hrw_lease(tool, request, connector_declares_singleton_writer) {
        let routing = current_hrw_lease_routing_config()?;
        enforce_hrw_lease_route(request, routing.as_ref())?;
    }

    // SECURITY: holder-bound tokens (`holder_node` claim present) must never
    // silently degrade to bearer tokens. Until fcp-host wires live holder-proof
    // signature verification against node attestations, fail closed here.
    if let Some(expected_holder) = verified_claims.get_holder_node() {
        let Some(holder_proof) = request.holder_proof.as_ref() else {
            return Err(HostError::PreflightFailed(format!(
                "capability token is holder-bound to `{expected_holder}`, but the request did not include holder_proof"
            )));
        };
        if holder_proof.holder_node.as_str() != expected_holder {
            return Err(HostError::PreflightFailed(format!(
                "holder_proof node `{}` does not match capability token holder_node `{expected_holder}`",
                holder_proof.holder_node.as_str()
            )));
        }
        return Err(HostError::PreflightFailed(format!(
            "capability token is holder-bound to `{expected_holder}`, but fcp-host does not yet verify holder_proof signatures for live requests"
        )));
    }

    let persisted_verify = state
        .lifecycle
        .verify_capability_token(&CapabilityTokenVerifyRequest {
            token_cbor_b64: capability_token_b64(&request.capability_token)?,
            operation_id: Some(request.operation.to_string()),
            connector_id: Some(request.connector_id.to_string()),
        })
        .await
        .map_err(|error| {
            HostError::PreflightFailed(format!("persisted capability verification failed: {error}"))
        })?;
    if !persisted_verify.valid {
        if let Some(reason) = authoritative_persisted_capability_rejection_reason(
            &persisted_verify,
            "persisted capability verification rejected the live request",
        ) {
            return Err(HostError::PreflightFailed(format!(
                "capability token rejected by host state: {reason}"
            )));
        }
    }

    let principal = claims_principal(verified_claims).ok_or_else(|| {
        HostError::PreflightFailed(
            "capability token is missing the subject or principal_id claim required for live execution".to_string(),
        )
    })?;
    if let Some(expected) = principal_override
        && expected != principal
    {
        return Err(HostError::PreflightFailed(format!(
            "request principal `{expected}` does not match capability token subject/principal_id `{principal}`"
        )));
    }

    verify_approval_tokens(
        &request.approval_tokens,
        state.approval_verifying_key.as_ref(),
    )?;

    let approval_required = tool
        .approval_mode
        .is_some_and(|mode| !matches!(mode, ApprovalMode::None));
    let request_input_hash = request_input_hash(&request.input)?;
    let zone_policy = state.lookup_zone_policy(&request.zone_id).await?;
    let receipt = simulate_policy_decision(&PolicySimulationInput {
        zone_policy,
        invoke_request: request.clone(),
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: approval_required,
        sanitizer_receipts: Vec::new(),
        related_object_ids: Vec::new(),
        request_object_id: None,
        request_input_hash: Some(request_input_hash),
        safety_tier: tool.safety_tier,
        principal: Some(principal.to_owned()),
        capability_id: Some(tool.capability.to_string()),
        provenance_record: None,
        now_ms: None,
        posture_attestation: None,
    })
    .map_err(|error| HostError::PreflightFailed(format!("policy evaluation failed: {error}")))?;

    if receipt.decision == Decision::Deny {
        return Err(HostError::PreflightFailed(format!(
            "policy denied live request: {}",
            receipt.reason_code
        )));
    }

    enforce_live_capability_constraints(
        request,
        verified_claims,
        principal,
        constraint_resource_uri.as_deref(),
    )?;
    state
        .registry
        .enforce_invoke_rate_limits(request, &introspection, principal)
        .await?;

    Ok(VerifiedLiveRequest {
        principal: principal.to_owned(),
        approval_required,
        safety_tier: tool.safety_tier,
    })
}

fn preflight_response_from_error(error: HostError) -> PreflightResponse {
    let reason = error.to_string();
    let mut response = PreflightResponse::denied(&reason);
    response.reason = Some(reason);
    response
}

fn track_verified_cancellation_owner(
    cancellation: &CancellationController,
    operation_id: &str,
    request: &InvokeRequest,
) -> HostResult<()> {
    let verified_claims = request
        .capability_token
        .raw()
        .claims_unverified()
        .map_err(|error| {
            HostError::Internal(format!(
                "verified live request lost readable capability claims before cancellation tracking: {error}"
            ))
        })?;
    let cancellation_owner = claims_principal(&verified_claims).ok_or_else(|| {
        HostError::Internal(
            "verified live request lost the subject/principal_id claim before cancellation tracking"
                .to_string(),
        )
    })?;
    cancellation.track_with_owner(operation_id, Some(cancellation_owner));
    Ok(())
}

async fn verified_cancellation_principal(
    state: &AppState,
    request: &CancellationRequest,
) -> HostResult<String> {
    let capability_token = request.capability_token.as_ref().ok_or_else(|| {
        HostError::PreflightFailed("capability token is required for /rpc/cancel-self".to_string())
    })?;
    let persisted_verify = state
        .lifecycle
        .verify_capability_token(&CapabilityTokenVerifyRequest {
            token_cbor_b64: capability_token_b64(capability_token)?,
            operation_id: Some(CANCEL_SELF_OPERATION_ID.to_string()),
            connector_id: Some(CANCEL_SELF_CONNECTOR_ID.to_string()),
        })
        .await
        .map_err(|error| {
            HostError::PreflightFailed(format!("persisted capability verification failed: {error}"))
        })?;
    if !persisted_verify.valid {
        let reason = persisted_verify
            .rejection_reasons
            .first()
            .cloned()
            .unwrap_or_else(|| {
                "persisted capability verification rejected the cancel-self request".to_string()
            });
        return Err(HostError::PreflightFailed(format!(
            "capability token rejected by host state: {reason}"
        )));
    }

    let verified_claims = capability_token
        .raw()
        .claims_unverified()
        .map_err(|error| {
            HostError::PreflightFailed(format!(
                "verified cancellation token lost readable capability claims: {error}"
            ))
        })?;
    if verified_claims.get_capability_id() != Some(CANCEL_SELF_CAPABILITY_ID) {
        return Err(HostError::PreflightFailed(format!(
            "/rpc/cancel-self requires `{CANCEL_SELF_CAPABILITY_ID}` capability token"
        )));
    }
    if let Some(expected_holder) = verified_claims.get_holder_node() {
        return Err(HostError::PreflightFailed(format!(
            "capability token is holder-bound to `{expected_holder}`, but /rpc/cancel-self does not accept holder-bound tokens"
        )));
    }

    let principal = claims_principal(&verified_claims)
        .map(str::trim)
        .filter(|principal| !principal.is_empty())
        .ok_or_else(|| {
            HostError::PreflightFailed(
                "capability token missing subject/principal_id claim".to_string(),
            )
        })?;
    Ok(principal.to_string())
}

async fn evaluate_live_preflight(
    state: &AppState,
    request: &InvokeRequest,
    principal_override: Option<&str>,
) -> PreflightResponse {
    let mut response = state
        .discovery
        .preflight(PreflightRequest {
            connector_id: request.connector_id.clone(),
            operation: request.operation.to_string(),
            params: Some(request.input.clone()),
            principal: principal_override.map(ToOwned::to_owned),
            zone_id: Some(request.zone_id.clone()),
        })
        .await;
    if !response.allowed {
        return response;
    }

    match verify_live_request(state, request, principal_override).await {
        Ok(verified) => {
            tracing::debug!(
                event = "live_request_verified",
                connector_id = %request.connector_id,
                operation = %request.operation,
                principal = %verified.principal,
                approval_required = verified.approval_required,
                safety_tier = ?verified.safety_tier,
                "live request auth verified"
            );
            response
        }
        Err(error) => {
            response.allowed = false;
            response.reason = Some(error.to_string());
            response
        }
    }
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
                    zone: Some(operation.request.zone_id.clone()),
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

async fn pin_state_response(
    lifecycle: &HostAdminStateStore,
    connector_id: &ConnectorId,
) -> PinStateResponse {
    PinStateResponse::new(connector_id, lifecycle.pinned_version(connector_id).await)
}

async fn rollout_status_response(
    lifecycle: &HostAdminStateStore,
    connector_id: &ConnectorId,
) -> Result<RolloutStatusResponse, LifecycleError> {
    let record = lifecycle
        .get(connector_id)
        .await?
        .ok_or_else(|| LifecycleError::NotFound {
            connector_id: connector_id.clone(),
        })?;
    let status = LifecycleStatus::from_record(&record, Utc::now(), false);
    let pinned_version = lifecycle.pinned_version(connector_id).await;
    Ok(RolloutStatusResponse {
        status,
        pinned: pinned_version.is_some(),
        pinned_version,
        canary_percent: record.canary_policy.canary_traffic_percent,
    })
}

fn log_startup_reconciliation(report: &fcp_host::StartupReconciliationReport) {
    tracing::info!(
        event = "startup_reconciliation",
        tracked_connectors = report.tracked_connectors,
        created_connectors = report.created_connectors,
        observed_updates = report.observed_updates,
        drifted_connectors = report.drifted_connectors,
        "startup reconciliation complete"
    );

    for entry in &report.entries {
        if let Some(drift) = entry.drift.as_ref() {
            tracing::warn!(
                event = "startup_reconciliation_drift",
                connector_id = %entry.connector_id,
                desired_state = ?entry.desired_state,
                observed_state_after = ?entry.observed_state_after,
                drift_kind = ?drift.kind,
                recovery_action = ?drift.recovery_action,
                message = %drift.message,
                "startup reconciliation detected connector drift"
            );
        }
    }
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

struct LoadedConnectorConfigs {
    configs: Vec<ConnectorConfig>,
    connectors_file: Option<PathBuf>,
}

fn resolve_connectors_file_path() -> HostResult<Option<PathBuf>> {
    Ok(read_optional_trimmed_env_string("FCP_HOST_CONNECTORS_FILE")?.map(PathBuf::from))
}

fn read_connector_configs_file(path: &std::path::Path) -> HostResult<Vec<ConnectorConfig>> {
    let raw = std::fs::read_to_string(path).map_err(|err| {
        HostError::Internal(format!(
            "failed to read connectors file '{}': {err}",
            path.display()
        ))
    })?;
    serde_json::from_str(&raw)
        .map_err(|err| HostError::InvalidFilter(format!("invalid connector config json: {err}")))
}

fn write_connector_configs_file(
    path: &std::path::Path,
    configs: &[ConnectorConfig],
) -> HostResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            HostError::Internal(format!(
                "failed to create connectors file parent '{}': {err}",
                parent.display()
            ))
        })?;
    }

    let encoded = serde_json::to_string_pretty(configs).map_err(|err| {
        HostError::Internal(format!(
            "failed to serialize connector inventory for '{}': {err}",
            path.display()
        ))
    })?;

    let mut temp_path = path.as_os_str().to_os_string();
    temp_path.push(".tmp");
    let temp_path = std::path::PathBuf::from(temp_path);

    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(encoded.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;

        #[cfg(not(windows))]
        std::fs::rename(&temp_path, path)?;

        #[cfg(windows)]
        {
            if path.exists() {
                std::fs::remove_file(path)?;
            }
            std::fs::rename(&temp_path, path)?;
        }

        Ok(())
    })();

    if write_result.is_err() && temp_path.exists() {
        let _ = std::fs::remove_file(&temp_path);
    }

    write_result.map_err(|err| {
        HostError::Internal(format!(
            "failed to safely write connectors file '{}': {err}",
            path.display()
        ))
    })
}

fn replace_connector_update(
    existing: &ConnectorConfig,
    incoming: &ConnectorConfig,
) -> ConnectorConfig {
    let mut updated = incoming.clone();
    updated.id = existing.id.clone();
    updated
}

fn load_connector_configs() -> HostResult<LoadedConnectorConfigs> {
    let connectors_file = resolve_connectors_file_path()?;
    let payload = if let Some(path) = connectors_file.as_ref() {
        Some(std::fs::read_to_string(path).map_err(|err| {
            HostError::Internal(format!(
                "failed to read connectors file '{}': {err}",
                path.display()
            ))
        })?)
    } else {
        read_optional_env_string("FCP_HOST_CONNECTORS")?
    };

    let Some(raw) = payload else {
        return Ok(LoadedConnectorConfigs {
            configs: Vec::new(),
            connectors_file,
        });
    };
    if raw.trim().is_empty() {
        return Ok(LoadedConnectorConfigs {
            configs: Vec::new(),
            connectors_file,
        });
    }

    let configs = serde_json::from_str(&raw)
        .map_err(|err| HostError::InvalidFilter(format!("invalid connector config json: {err}")))?;
    Ok(LoadedConnectorConfigs {
        configs,
        connectors_file,
    })
}

fn resolve_zone_policies_file_path() -> HostResult<Option<PathBuf>> {
    Ok(read_optional_trimmed_env_string("FCP_HOST_ZONE_POLICIES_FILE")?.map(PathBuf::from))
}

fn load_zone_policies() -> HostResult<HashMap<ZoneId, ZonePolicyObject>> {
    let Some(path) = resolve_zone_policies_file_path()? else {
        return Ok(HashMap::new());
    };
    let raw = std::fs::read_to_string(&path).map_err(|err| {
        HostError::Internal(format!(
            "failed to read zone policies file '{}': {err}",
            path.display()
        ))
    })?;
    parse_zone_policies_json(&raw)
}

fn parse_zone_policies_json(raw: &str) -> HostResult<HashMap<ZoneId, ZonePolicyObject>> {
    if raw.trim().is_empty() {
        return Ok(HashMap::new());
    }

    let parsed: HashMap<String, ZonePolicyObject> = serde_json::from_str(raw)
        .map_err(|err| HostError::InvalidFilter(format!("invalid zone policies json: {err}")))?;
    let mut policies = HashMap::new();
    for (raw_zone, policy) in parsed {
        let zone_id: ZoneId = raw_zone.parse().map_err(|err| {
            HostError::InvalidFilter(format!("invalid zone policy key '{raw_zone}': {err}"))
        })?;
        if policy.zone_id != zone_id {
            return Err(HostError::InvalidFilter(format!(
                "zone policy key '{}' does not match policy zone_id '{}'",
                zone_id.as_str(),
                policy.zone_id.as_str()
            )));
        }
        policies.insert(zone_id, policy);
    }
    Ok(policies)
}

fn resolve_hybrid_owner_production_verifier()
-> HostResult<Option<Arc<HybridOwnerProductionVerifier>>> {
    let Some(path) = read_optional_trimmed_env_string(HYBRID_OWNER_CONTEXT_FILE_ENV)? else {
        // br-jhbk1: surface the unconfigured-verifier state at startup
        // so operators see WHEN the V4 hybrid-owner check is disabled.
        // The runtime path now fail-closes on requests carrying the
        // hybrid-owner evidence tag (see verify_live_hybrid_owner_capability),
        // but the warn here makes the deployment-time misconfiguration
        // visible BEFORE the first failed request arrives.
        tracing::warn!(
            env_var = HYBRID_OWNER_CONTEXT_FILE_ENV,
            "FCP host is starting without a hybrid-owner verifier; \
             requests carrying hybrid-owner evidence tags will be rejected \
             at preflight (br-jhbk1). Set the env var to enable V4 \
             hybrid-owner capability verification."
        );
        return Ok(None);
    };
    let raw = std::fs::read_to_string(&path).map_err(|err| {
        HostError::Internal(format!(
            "failed to read hybrid owner context file '{}': {err}",
            path
        ))
    })?;
    let config: HybridOwnerProductionConfig = serde_json::from_str(&raw).map_err(|err| {
        HostError::InvalidFilter(format!("invalid hybrid owner context json: {err}"))
    })?;
    Ok(Some(Arc::new(HybridOwnerProductionVerifier::from_config(
        config,
    ))))
}

fn resolve_self_check_timeout() -> HostResult<Option<Duration>> {
    let Some(raw) = read_optional_trimmed_env_string("FCP_HOST_SELF_CHECK_TIMEOUT_MS")? else {
        return Ok(None);
    };
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
    let Some(raw) = read_optional_trimmed_env_string(name)? else {
        return Ok(None);
    };
    parse_env_bool(name, &raw).map(Some)
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
    let Some(raw) = read_optional_trimmed_env_string(name)? else {
        return Ok(None);
    };
    let parsed = raw
        .parse()
        .map_err(|err| HostError::InvalidFilter(format!("invalid {name}: {err}")))?;
    Ok(Some(parsed))
}

fn read_env_usize(name: &str) -> HostResult<Option<usize>> {
    let Some(raw) = read_optional_trimmed_env_string(name)? else {
        return Ok(None);
    };
    let parsed = raw
        .parse()
        .map_err(|err| HostError::InvalidFilter(format!("invalid {name}: {err}")))?;
    Ok(Some(parsed))
}

fn resolve_bind_target() -> HostResult<BindTarget> {
    let raw =
        read_optional_env_string("FCP_HOST_BIND")?.unwrap_or_else(|| "127.0.0.1:9090".to_string());
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
    match parse_cli_action()? {
        CliAction::Run => {}
        CliAction::PrintHelp => {
            print_cli_help();
            return Ok(());
        }
        CliAction::PrintVersion => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
    }
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
    let capability_verifying_key = resolve_verifying_key(
        "FCP_HOST_CAPABILITY_PUBLIC_KEY",
        "FCP_HOST_CAPABILITY_PUBLIC_KEY_FILE",
    )?;
    let approval_verifying_key = resolve_verifying_key(
        "FCP_HOST_APPROVAL_PUBLIC_KEY",
        "FCP_HOST_APPROVAL_PUBLIC_KEY_FILE",
    )?
    .or_else(|| capability_verifying_key.clone());

    let loaded_configs = load_connector_configs()?;
    if loaded_configs.configs.is_empty() {
        tracing::warn!("no connectors configured; doctor self-checks will fail");
    }
    let deployment_classification = current_deployment_classification();
    emit_boot_log(&deployment_classification);
    let operational_model = current_operational_model_selection(&deployment_classification)?;
    emit_operational_model_selection_log(&operational_model);
    let zone_policies = load_zone_policies()?;

    let registry = Arc::new(
        SubprocessRegistry::from_configs(
            loaded_configs.configs,
            capability_verifying_key
                .as_ref()
                .map(Ed25519VerifyingKey::to_bytes),
        )
        .await?,
    );
    let doctor = match resolve_self_check_timeout()? {
        Some(timeout) => DoctorService::with_timeout(Arc::clone(&registry), timeout),
        None => DoctorService::new(Arc::clone(&registry)),
    };
    let budget = Arc::new(BudgetPolicyEngine::new());
    let discovery = Arc::new(DiscoveryEndpoint::new(
        Arc::clone(&registry),
        Arc::clone(&budget),
    ));
    let lifecycle = Arc::new(HostAdminStateStore::from_env()?);
    let startup_inventory = registry.list().await;
    let startup_reconciliation = lifecycle
        .reconcile_registered_connectors(&startup_inventory)
        .await
        .map_err(map_lifecycle_host_error)?;
    log_startup_reconciliation(&startup_reconciliation);
    let rollout = Arc::new(RolloutController::new(
        Arc::clone(&registry),
        Arc::clone(&lifecycle),
    ));
    let supply_chain = Arc::new(SupplyChainGate::with_config(
        resolve_supply_chain_gate_config()?,
    ));
    let hybrid_owner_verifier = resolve_hybrid_owner_production_verifier()?;
    let cancellation = Arc::new(CancellationController::new());
    let state = Arc::new(AppState {
        registry,
        doctor,
        budget,
        discovery,
        cancellation,
        lifecycle,
        rollout,
        supply_chain,
        capability_verifying_key,
        revocation_cascade: Arc::new(RevocationCascadeVerifier::default()),
        hybrid_owner_verifier,
        approval_verifying_key,
        admin_bearer_token: resolve_admin_bearer_token()?,
        connectors_file: loaded_configs.connectors_file,
        zone_policies: Arc::new(RwLock::new(zone_policies)),
        invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
        started_at: Instant::now(),
    });

    let protected_routes = Router::new()
        .route(
            // GET leaks supply-chain provenance (artifact hash, SLSA level,
            // builder identity, SupplyChainSignature, trust-root id) — every
            // field a downstream substitution attacker would want to
            // enumerate before impersonating a signer. It is now
            // co-routed with the POST register handler inside
            // `protected_routes` so the admin bearer middleware gates both
            // verbs. Closes bead flywheel_connectors-qeapt.
            "/rpc/connectors/{connector_id}/artifact",
            get(connector_artifact_metadata_handler).post(connector_artifact_register_handler),
        )
        .route(
            "/rpc/connectors/{connector_id}/config",
            get(connector_config_snapshot_handler),
        )
        .route(
            "/rpc/connectors/{connector_id}/config/revisions",
            get(connector_config_revisions_handler),
        )
        .route(
            "/rpc/connectors/{connector_id}/config/revisions/{revision_id}",
            get(connector_config_revision_handler),
        )
        .route(
            "/rpc/connectors/{connector_id}/config/diff",
            post(connector_config_diff_handler),
        )
        .route(
            "/rpc/connectors/{connector_id}/config/validate",
            post(connector_config_validate_handler),
        )
        .route(
            "/rpc/connectors/{connector_id}/config/apply",
            post(connector_config_apply_handler),
        )
        .route(
            "/rpc/connectors/{connector_id}/config/rollback",
            post(connector_config_rollback_handler),
        )
        .route(
            "/rpc/connectors/apply",
            post(connector_inventory_apply_handler),
        )
        .route(
            "/rpc/supply-chain/verify",
            post(supply_chain_verify_handler),
        )
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
        .route(
            "/rpc/lifecycle/{connector_id}",
            post(lifecycle_transition_handler).get(lifecycle_record_handler),
        )
        .route("/rpc/admin/journal", post(journal_query_handler))
        .route(
            "/rpc/admin/journal/{connector_id}",
            get(journal_connector_handler),
        )
        .route("/rpc/admin/logs", post(log_query_handler))
        .route("/rpc/admin/receipts", post(receipt_query_handler))
        .route(
            "/rpc/admin/simulate-receipts",
            post(simulate_receipt_query_handler),
        )
        .route("/rpc/admin/events", post(event_query_handler))
        .route(
            "/rpc/admin/events/acknowledge",
            post(event_acknowledge_handler),
        )
        // br-71lku: /rpc/cancel and /rpc/operations/cancel were
        // previously mounted on the public app router below, where
        // cancel_handler trusted only the spoofable X-Principal
        // header for principal assertion. Any unauthenticated caller
        // could therefore POST a cancel for a known operation_id +
        // matching X-Principal value and have
        // CancellationController::cancel accept it on plain string
        // equality. Moving both routes into protected_routes gates
        // them behind admin_auth_middleware (Bearer token + owner
        // zone header), closing the auth-bypass vector flagged in
        // the bead. Tenant self-cancel via capability-token-driven
        // principal is tracked as separate follow-up work — the
        // immediate fix is to deny the spoofed-header path.
        .route("/rpc/cancel", post(cancel_handler))
        .route("/rpc/operations/cancel", post(cancel_handler))
        .route_layer(from_fn_with_state(
            Arc::clone(&state),
            admin_auth_middleware,
        ));

    let app = Router::new()
        .route("/doctor", post(doctor_handler))
        .route("/rpc/discover", post(discover_handler))
        .route("/rpc/connectors/{connector_id}", get(connector_handler))
        .route(
            "/rpc/connectors/{connector_id}/status",
            get(connector_status_handler),
        )
        // `/rpc/connectors/{id}/artifact` GET moved into `protected_routes`
        // alongside the register/install/update/rollback POSTs so the admin
        // bearer middleware gates supply-chain provenance reads. Prior
        // TODO(review) marker and ungated GET: see bead
        // flywheel_connectors-qeapt.
        .route("/rpc/introspect/{connector_id}", get(introspect_handler))
        .route("/rpc/invoke", post(invoke_handler))
        // /rpc/cancel and /rpc/operations/cancel moved into
        // protected_routes (br-71lku — see comment there). Public
        // owner-scoped self-cancel now lives at /rpc/cancel-self and
        // authenticates from a verified capability token rather than
        // X-Principal.
        .route("/rpc/cancel-self", post(cancel_self_handler))
        .route("/rpc/batch", post(batch_invoke_handler))
        .route("/rpc/batch-invoke", post(batch_invoke_handler))
        .route("/rpc/preflight", post(preflight_handler))
        .route("/rpc/simulate", post(simulate_handler))
        .route("/rpc/budget/report", post(budget_report_handler))
        .route("/rpc/health", get(health_handler))
        .merge(protected_routes)
        .with_state(Arc::clone(&state));

    let (shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);

    // Spawn signal handler task.
    let signal_state = Arc::clone(&state);
    task::spawn_detached(async move {
        signal_handler_loop(signal_state, shutdown_tx).await;
    });

    match bind_target {
        BindTarget::Tcp(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|err| HostError::Internal(format!("tcp bind error: {err}")))?;
            tracing::info!(transport = "tcp", %addr, "fcp-host listening");
            serve_tcp(listener, app, shutdown_rx).await?;
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
            serve_unix(listener, app, shutdown_rx).await?;
        }
    }

    tracing::info!(event = "host_shutdown_complete", "fcp-host exiting cleanly");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal handling
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
async fn signal_handler_loop(
    state: Arc<AppState>,
    shutdown_tx: fcp_async_core::channel::watch::Sender<bool>,
) {
    use fcp_async_core::signal::{sighup, sigint, sigterm};
    use futures_util::FutureExt;

    let mut sighup_stream = match sighup() {
        Ok(stream) => stream,
        Err(err) => {
            tracing::error!(
                event = "signal_registration_failed",
                signal = "SIGHUP",
                error = %err,
                "failed to register SIGHUP handler; initiating shutdown"
            );
            let _ = shutdown_tx.send(true);
            return;
        }
    };
    let mut sigterm_stream = match sigterm() {
        Ok(stream) => stream,
        Err(err) => {
            tracing::error!(
                event = "signal_registration_failed",
                signal = "SIGTERM",
                error = %err,
                "failed to register SIGTERM handler; initiating shutdown"
            );
            let _ = shutdown_tx.send(true);
            return;
        }
    };
    let mut sigint_stream = match sigint() {
        Ok(stream) => stream,
        Err(err) => {
            tracing::error!(
                event = "signal_registration_failed",
                signal = "SIGINT",
                error = %err,
                "failed to register SIGINT handler; initiating shutdown"
            );
            let _ = shutdown_tx.send(true);
            return;
        }
    };

    loop {
        let sighup_recv = sighup_stream.recv().fuse();
        let sigterm_recv = sigterm_stream.recv().fuse();
        let sigint_recv = sigint_stream.recv().fuse();
        futures_util::pin_mut!(sighup_recv, sigterm_recv, sigint_recv);

        futures_util::select! {
            delivered = sighup_recv => {
                if delivered.is_none() {
                    break;
                }
                tracing::info!(
                    event = "sighup_received",
                    "reloading connector configuration"
                );
                match reload_connectors(&state).await {
                    Ok(count) => {
                        tracing::info!(
                            event = "config_reload_complete",
                            connectors_reloaded = count,
                            "configuration reloaded successfully"
                        );
                    }
                    Err(err) => {
                        tracing::error!(
                            event = "config_reload_failed",
                            error = %err,
                            "configuration reload failed; continuing with previous config"
                        );
                    }
                }
            }
            delivered = sigterm_recv => {
                if delivered.is_none() {
                    break;
                }
                tracing::info!(event = "sigterm_received", "initiating graceful shutdown");
                let _ = shutdown_tx.send(true);
                break;
            }
            delivered = sigint_recv => {
                if delivered.is_none() {
                    break;
                }
                tracing::info!(event = "sigint_received", "initiating graceful shutdown");
                let _ = shutdown_tx.send(true);
                break;
            }
        }
    }
}

#[cfg(not(unix))]
async fn signal_handler_loop(
    _state: Arc<AppState>,
    shutdown_tx: fcp_async_core::channel::watch::Sender<bool>,
) {
    // On non-Unix platforms, wait for Ctrl+C through the native asupersync
    // signal shim instead of a compatibility bridge.
    if let Err(err) = fcp_async_core::signal::ctrl_c().await {
        tracing::error!(
            event = "signal_registration_failed",
            signal = "CTRL_C",
            error = %err,
            "failed to register Ctrl+C handler; initiating shutdown"
        );
        let _ = shutdown_tx.send(true);
        return;
    }
    tracing::info!(event = "ctrl_c_received", "initiating graceful shutdown");
    let _ = shutdown_tx.send(true);
}

/// Reload connector configuration from disk without restarting the host.
///
/// Re-reads the connectors config file, applies changes to the subprocess
/// registry (adding/updating/removing connectors), and reconciles the
/// lifecycle state with the updated inventory.
#[cfg(unix)]
async fn reload_connectors(state: &AppState) -> Result<usize, HostError> {
    let loaded = load_connector_configs()?;
    let count = loaded.configs.len();

    // Apply the new config set (handles add/update/remove diff).
    let report = state.registry.apply_configs(loaded.configs).await?;
    tracing::info!(
        event = "config_reload_applied",
        added = report.added.len(),
        updated = report.updated.len(),
        removed = report.removed.len(),
        unchanged = report.unchanged.len(),
        registry_version = report.registry_version,
        "registry updated from reloaded config"
    );

    // Reconcile lifecycle state with the new inventory.
    let inventory = state.registry.list().await;
    let reconciliation = state
        .lifecycle
        .reconcile_registered_connectors(&inventory)
        .await
        .map_err(|e| HostError::Internal(format!("reconciliation failed: {e}")))?;
    log_startup_reconciliation(&reconciliation);

    Ok(count)
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

async fn budget_report_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BudgetReportRequest>,
) -> Result<Json<BudgetReportResponse>, (StatusCode, String)> {
    let started_at = Instant::now();
    tracing::debug!(
        event = "budget_report_request",
        zone_id = request.zone_id.as_deref().unwrap_or("*"),
        "processing budget report request"
    );

    let zone_filter = request
        .zone_id
        .as_deref()
        .map(|zone_id| {
            zone_id.parse().map_err(|err| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid zone_id '{zone_id}': {err}"),
                )
            })
        })
        .transpose()?;

    let report = state.budget.report(zone_filter.as_ref()).await;
    tracing::debug!(
        event = "budget_report_response",
        zone_count = report.zones.len(),
        duration_ms = started_at.elapsed().as_millis() as u64,
        "budget report request complete"
    );

    Ok(Json(report))
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

async fn connector_status_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
) -> Result<Json<ConnectorAdminStatus>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "connector_status_request",
        connector_id = %connector_id,
        "processing connector admin status request"
    );

    match state.lifecycle.connector_status(&connector_id).await {
        Ok(status) => {
            tracing::debug!(
                event = "connector_status_response",
                connector_id = %connector_id,
                desired_state = ?status.desired_state,
                observed_state = ?status.observed_state,
                drifted = status.drift.is_some(),
                duration_ms = started_at.elapsed().as_millis() as u64,
                "connector admin status request complete"
            );
            Ok(Json(status))
        }
        Err(err) => {
            let host_error = map_lifecycle_host_error(err);
            tracing::warn!(
                event = "connector_status_error",
                connector_id = %connector_id,
                error = %host_error,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "connector admin status request failed"
            );
            Err(map_host_error(host_error))
        }
    }
}

async fn connector_artifact_metadata_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
) -> Result<Json<ConnectorArtifactMetadataResponse>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "connector_artifact_metadata_request",
        connector_id = %connector_id,
        "processing connector artifact metadata request"
    );

    match state
        .lifecycle
        .connector_artifact_metadata(&connector_id)
        .await
    {
        Ok(response) => {
            tracing::debug!(
                event = "connector_artifact_metadata_response",
                connector_id = %connector_id,
                has_artifact = response.artifact.is_some(),
                duration_ms = started_at.elapsed().as_millis() as u64,
                "connector artifact metadata request complete"
            );
            Ok(Json(response))
        }
        Err(err) => {
            let host_error = map_lifecycle_host_error(err);
            tracing::warn!(
                event = "connector_artifact_metadata_error",
                connector_id = %connector_id,
                error = %host_error,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "connector artifact metadata request failed"
            );
            Err(map_host_error(host_error))
        }
    }
}

async fn connector_artifact_register_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    Json(request): Json<ConnectorArtifactRegistrationRequest>,
) -> Result<Json<ConnectorArtifactRegistrationResponse>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "connector_artifact_register_request",
        connector_id = %connector_id,
        dry_run = request.dry_run,
        source_kind = ?request.provenance.source_kind,
        has_placement = request.placement.is_some(),
        "processing connector artifact registration request"
    );

    match state
        .lifecycle
        .register_connector_artifact(&connector_id, &request)
        .await
    {
        Ok(response) => {
            tracing::debug!(
                event = "connector_artifact_register_response",
                connector_id = %connector_id,
                accepted = response.accepted,
                dry_run = response.dry_run,
                rejected = response.rejection.is_some(),
                duration_ms = started_at.elapsed().as_millis() as u64,
                "connector artifact registration request complete"
            );
            Ok(Json(response))
        }
        Err(err) => {
            let host_error = map_lifecycle_host_error(err);
            tracing::warn!(
                event = "connector_artifact_register_error",
                connector_id = %connector_id,
                error = %host_error,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "connector artifact registration request failed"
            );
            Err(map_host_error(host_error))
        }
    }
}

async fn connector_inventory_apply_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ConnectorInventoryMutationRequest>,
) -> Result<Json<ConnectorInventoryMutationResponse>, (StatusCode, String)> {
    let connector_id = request.connector.id.clone();
    let started_at = Instant::now();
    tracing::debug!(
        event = "connector_inventory_apply_request",
        connector_id = %connector_id,
        kind = ?request.kind,
        "processing live connector inventory mutation"
    );

    let connectors_file = state.connectors_file.clone().ok_or_else(|| {
        map_host_error(HostError::Unavailable(
            "live connector inventory mutation requires FCP_HOST_CONNECTORS_FILE to be configured"
                .to_string(),
        ))
    })?;

    let previous_configs = read_connector_configs_file(&connectors_file).map_err(map_host_error)?;
    let mut next_configs = previous_configs.clone();
    let previous = previous_configs
        .iter()
        .find(|entry| entry.id == request.connector.id)
        .cloned();

    match request.kind {
        ConnectorInventoryMutationKind::Install => {
            if previous.is_some() {
                return Err(map_host_error(HostError::InvalidFilter(format!(
                    "connector '{}' is already present in the managed inventory",
                    request.connector.id
                ))));
            }
            next_configs.push(request.connector.clone());
        }
        ConnectorInventoryMutationKind::Update => {
            let target_index = next_configs
                .iter()
                .position(|entry| entry.id == request.connector.id)
                .ok_or_else(|| {
                    map_host_error(HostError::ConnectorNotFound(request.connector.id.clone()))
                })?;
            next_configs[target_index] =
                replace_connector_update(&next_configs[target_index], &request.connector);
        }
    }

    let (apply, current_inventory, current, admin_state) = if request.dry_run {
        let preview = state
            .registry
            .preview_configs(next_configs.clone())
            .await
            .map_err(map_host_error)?;
        let current = next_configs
            .iter()
            .find(|entry| entry.id == request.connector.id)
            .cloned()
            .ok_or_else(|| {
                map_host_error(HostError::Internal(format!(
                    "connector '{}' was missing from the preview inventory",
                    request.connector.id
                )))
            })?;
        (preview, next_configs.clone(), current, None)
    } else {
        write_connector_configs_file(&connectors_file, &next_configs).map_err(map_host_error)?;
        let apply = match state.registry.apply_configs(next_configs.clone()).await {
            Ok(report) => report,
            Err(err) => {
                let rollback_result =
                    write_connector_configs_file(&connectors_file, &previous_configs);
                let rollback_note = match rollback_result {
                    Ok(()) => "connectors file rolled back".to_string(),
                    Err(rollback_err) => {
                        format!("connectors file rollback also failed: {}", rollback_err)
                    }
                };
                return Err(map_host_error(HostError::Internal(format!(
                    "failed to apply live connector inventory mutation for '{}': {err}; {rollback_note}",
                    request.connector.id
                ))));
            }
        };

        let current_inventory = state.registry.inventory().await;
        let current = match current_inventory
            .iter()
            .find(|entry| entry.id == request.connector.id)
            .cloned()
        {
            Some(entry) => entry,
            None => {
                let rollback_note =
                    rollback_connector_inventory(&state, &connectors_file, &previous_configs).await;
                return Err(map_host_error(HostError::Internal(format!(
                    "connector '{}' was missing from the live registry immediately after apply; {rollback_note}",
                    request.connector.id
                ))));
            }
        };
        let admin_state = match state
            .lifecycle
            .reconcile_registered_connectors(&state.registry.list().await)
            .await
        {
            Ok(report) => report,
            Err(err) => {
                let rollback_note =
                    rollback_connector_inventory(&state, &connectors_file, &previous_configs).await;
                return Err(map_host_error(HostError::Internal(format!(
                    "failed to reconcile admin state after live connector inventory mutation for '{}': {}; {rollback_note}",
                    request.connector.id,
                    map_lifecycle_host_error(err)
                ))));
            }
        };
        (apply, current_inventory, current, Some(admin_state))
    };

    tracing::info!(
        event = "connector_inventory_apply_response",
        connector_id = %connector_id,
        kind = ?request.kind,
        dry_run = request.dry_run,
        registry_version = apply.registry_version,
        inventory_size = current_inventory.len(),
        duration_ms = started_at.elapsed().as_millis() as u64,
        "live connector inventory mutation complete"
    );

    Ok(Json(ConnectorInventoryMutationResponse {
        kind: request.kind,
        dry_run: request.dry_run,
        connectors_file: connectors_file.display().to_string(),
        previous,
        current,
        inventory_size: current_inventory.len(),
        apply,
        admin_state: admin_state.unwrap_or_else(|| StartupReconciliationReport {
            reconciled_at: Utc::now(),
            tracked_connectors: current_inventory.len(),
            created_connectors: 0,
            observed_updates: 0,
            drifted_connectors: 0,
            entries: Vec::new(),
        }),
    }))
}

#[derive(Debug, Clone)]
struct ConnectorConfigContext {
    raw_payload: Value,
    current: SanitizedConnectorConfig,
    connector_state: Option<ConnectorAdminState>,
}

fn connector_config_payload(config: &ConnectorConfig) -> Value {
    config.config.clone().unwrap_or_else(|| json!({}))
}

fn normalize_connector_config_payload(payload: Value) -> Option<Value> {
    match payload {
        Value::Object(map) if map.is_empty() => None,
        other => Some(other),
    }
}

fn find_connector_inventory_entry<'a>(
    inventory: &'a [ConnectorConfig],
    connector_id: &ConnectorId,
) -> Option<&'a ConnectorConfig> {
    inventory
        .iter()
        .find(|entry| entry.id == connector_id.as_str())
}

async fn load_connector_config_context(
    state: &AppState,
    connector_id: &ConnectorId,
) -> Result<ConnectorConfigContext, HostError> {
    let inventory = state.registry.inventory().await;
    let inventory_entry = find_connector_inventory_entry(&inventory, connector_id)
        .cloned()
        .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;
    let raw_payload = connector_config_payload(&inventory_entry);
    let current = SanitizedConnectorConfig::from_payload(raw_payload.clone())
        .map_err(map_lifecycle_host_error)?;
    let connector_state = state.lifecycle.connector_state(connector_id).await;
    Ok(ConnectorConfigContext {
        raw_payload,
        current,
        connector_state,
    })
}

fn current_config_revision_id(context: &ConnectorConfigContext) -> Option<u64> {
    context
        .connector_state
        .as_ref()
        .and_then(|state| state.active_config_revision_id)
}

fn current_config_snapshot_source(
    context: &ConnectorConfigContext,
) -> ConnectorConfigSnapshotSource {
    if context
        .connector_state
        .as_ref()
        .and_then(ConnectorAdminState::active_config_revision)
        .is_some_and(|revision| revision.payload_digest == context.current.payload_digest)
    {
        ConnectorConfigSnapshotSource::ActiveRevision
    } else {
        ConnectorConfigSnapshotSource::ManagedInventory
    }
}

fn connector_config_snapshot_from_context(
    connector_id: &ConnectorId,
    context: &ConnectorConfigContext,
) -> ConnectorConfigSnapshot {
    let (active_revision_id, active_revision, revision_count, last_journal_sequence) = context
        .connector_state
        .as_ref()
        .map_or((None, None, 0, 0), |state| {
            (
                state.active_config_revision_id,
                state.active_config_revision().cloned(),
                state.config_revisions.len(),
                state.last_journal_sequence,
            )
        });
    ConnectorConfigSnapshot {
        connector_id: connector_id.clone(),
        current: context.current.clone(),
        source: current_config_snapshot_source(context),
        active_revision_id,
        active_revision,
        revision_count,
        last_journal_sequence,
    }
}

fn connector_config_revisions_from_context(
    connector_id: &ConnectorId,
    context: &ConnectorConfigContext,
) -> ConnectorConfigRevisionsResponse {
    let (active_revision_id, revision_count, last_journal_sequence, revisions) = context
        .connector_state
        .as_ref()
        .map_or((None, 0, 0, Vec::new()), |state| {
            (
                state.active_config_revision_id,
                state.config_revisions.len(),
                state.last_journal_sequence,
                state.config_revisions.clone(),
            )
        });
    ConnectorConfigRevisionsResponse {
        connector_id: connector_id.clone(),
        active_revision_id,
        revision_count,
        last_journal_sequence,
        revisions,
    }
}

fn find_config_revision(
    context: &ConnectorConfigContext,
    connector_id: &ConnectorId,
    revision_id: u64,
) -> Result<ConfigRevisionRecord, HostError> {
    context
        .connector_state
        .as_ref()
        .and_then(|state| state.config_revision(revision_id))
        .cloned()
        .ok_or_else(|| {
            HostError::InvalidFilter(format!(
                "config revision '{revision_id}' was not found for connector '{connector_id}'"
            ))
        })
}

fn ensure_expected_config_revision(
    connector_id: &ConnectorId,
    expected: Option<u64>,
    current: Option<u64>,
) -> Result<(), HostError> {
    match (expected, current) {
        (Some(expected), Some(current)) if expected != current => {
            Err(HostError::InvalidFilter(format!(
                "connector '{connector_id}' is at config revision {current}, expected {expected}"
            )))
        }
        (Some(expected), None) => Err(HostError::InvalidFilter(format!(
            "connector '{connector_id}' has no active config revision, expected {expected}"
        ))),
        _ => Ok(()),
    }
}

fn next_inventory_with_config(
    mut inventory: Vec<ConnectorConfig>,
    connector_id: &ConnectorId,
    payload: Value,
) -> Result<Vec<ConnectorConfig>, HostError> {
    let entry = inventory
        .iter_mut()
        .find(|entry| entry.id == connector_id.as_str())
        .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;
    entry.config = normalize_connector_config_payload(payload);
    Ok(inventory)
}

async fn rollback_connector_inventory(
    state: &AppState,
    connectors_file: &std::path::Path,
    previous_configs: &[ConnectorConfig],
) -> String {
    let file_note = match write_connector_configs_file(connectors_file, previous_configs) {
        Ok(()) => "connectors file rolled back".to_string(),
        Err(err) => format!("connectors file rollback also failed: {err}"),
    };
    let registry_note = match state
        .registry
        .apply_configs(previous_configs.to_vec())
        .await
    {
        Ok(_) => "live registry rolled back".to_string(),
        Err(err) => format!("live registry rollback also failed: {err}"),
    };
    let lifecycle_note = match state
        .lifecycle
        .reconcile_registered_connectors(&state.registry.list().await)
        .await
    {
        Ok(_) => "admin state reconciled after rollback".to_string(),
        Err(err) => format!(
            "admin-state rollback reconciliation also failed: {}",
            map_lifecycle_host_error(err)
        ),
    };
    format!("{file_note}; {registry_note}; {lifecycle_note}")
}

async fn apply_connector_config_payload(
    state: &AppState,
    connector_id: &ConnectorId,
    payload: Value,
    expected_active_revision_id: Option<u64>,
    created_by: Option<String>,
    change_reason: Option<String>,
) -> Result<ConnectorConfigApplyResponse, HostError> {
    let current_context = load_connector_config_context(state, connector_id).await?;
    ensure_expected_config_revision(
        connector_id,
        expected_active_revision_id,
        current_config_revision_id(&current_context),
    )?;

    let candidate = SanitizedConnectorConfig::from_payload(payload.clone())
        .map_err(map_lifecycle_host_error)?;
    let diff = diff_sanitized_config_values(&current_context.raw_payload, &payload)
        .map_err(map_lifecycle_host_error)?;
    if diff.is_empty() && candidate.payload_digest == current_context.current.payload_digest {
        return Ok(ConnectorConfigApplyResponse {
            connector_id: connector_id.clone(),
            changed: false,
            previous_active_revision_id: current_config_revision_id(&current_context),
            current_active_revision_id: current_config_revision_id(&current_context),
            previous: None,
            current: current_context.current.clone(),
            diff,
            revision: None,
            apply: None,
            admin_state: None,
        });
    }

    let connectors_file = state.connectors_file.clone().ok_or_else(|| {
        HostError::Unavailable(
            "live connector config mutation requires FCP_HOST_CONNECTORS_FILE to be configured"
                .to_string(),
        )
    })?;
    let previous_configs = read_connector_configs_file(&connectors_file)?;
    let next_configs = next_inventory_with_config(previous_configs.clone(), connector_id, payload)?;

    write_connector_configs_file(&connectors_file, &next_configs)?;
    let apply = match state.registry.apply_configs(next_configs).await {
        Ok(report) => report,
        Err(err) => {
            let rollback_note =
                rollback_connector_inventory(state, &connectors_file, &previous_configs).await;
            return Err(HostError::Internal(format!(
                "failed to apply live connector config mutation for '{connector_id}': {err}; {rollback_note}"
            )));
        }
    };

    let current_inventory = state.registry.inventory().await;
    let current_entry = match find_connector_inventory_entry(&current_inventory, connector_id)
        .cloned()
    {
        Some(entry) => entry,
        None => {
            let rollback_note =
                rollback_connector_inventory(state, &connectors_file, &previous_configs).await;
            return Err(HostError::Internal(format!(
                "connector '{connector_id}' was missing from the live registry immediately after config apply; {rollback_note}"
            )));
        }
    };
    let current_payload = connector_config_payload(&current_entry);
    let current = SanitizedConnectorConfig::from_payload(current_payload.clone())
        .map_err(map_lifecycle_host_error)?;
    let admin_state = match state
        .lifecycle
        .reconcile_registered_connectors(&state.registry.list().await)
        .await
    {
        Ok(report) => report,
        Err(err) => {
            let rollback_note =
                rollback_connector_inventory(state, &connectors_file, &previous_configs).await;
            return Err(HostError::Internal(format!(
                "failed to reconcile admin state after live connector config mutation for '{connector_id}': {}; {rollback_note}",
                map_lifecycle_host_error(err)
            )));
        }
    };
    let revision = match state
        .lifecycle
        .append_config_revision(
            connector_id,
            current_payload.clone(),
            created_by,
            change_reason,
        )
        .await
    {
        Ok(revision) => revision,
        Err(err) => {
            let rollback_note =
                rollback_connector_inventory(state, &connectors_file, &previous_configs).await;
            return Err(HostError::Internal(format!(
                "failed to persist config revision for '{connector_id}': {}; {rollback_note}",
                map_lifecycle_host_error(err)
            )));
        }
    };
    let diff = diff_sanitized_config_values(&current_context.raw_payload, &current_payload)
        .map_err(map_lifecycle_host_error)?;

    Ok(ConnectorConfigApplyResponse {
        connector_id: connector_id.clone(),
        changed: true,
        previous_active_revision_id: current_config_revision_id(&current_context),
        current_active_revision_id: Some(revision.revision_id),
        previous: Some(current_context.current),
        current,
        diff,
        revision: Some(revision),
        apply: Some(apply),
        admin_state: Some(admin_state),
    })
}

async fn connector_config_snapshot_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
) -> Result<Json<ConnectorConfigSnapshot>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "connector_config_snapshot_request",
        connector_id = %connector_id,
        "processing connector config snapshot request"
    );
    let context = load_connector_config_context(&state, &connector_id)
        .await
        .map_err(map_host_error)?;
    let response = connector_config_snapshot_from_context(&connector_id, &context);
    tracing::debug!(
        event = "connector_config_snapshot_response",
        connector_id = %connector_id,
        source = ?response.source,
        revision_count = response.revision_count,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "connector config snapshot request complete"
    );
    Ok(Json(response))
}

async fn connector_config_revisions_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
) -> Result<Json<ConnectorConfigRevisionsResponse>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "connector_config_revisions_request",
        connector_id = %connector_id,
        "processing connector config revision history request"
    );
    let context = load_connector_config_context(&state, &connector_id)
        .await
        .map_err(map_host_error)?;
    let response = connector_config_revisions_from_context(&connector_id, &context);
    tracing::debug!(
        event = "connector_config_revisions_response",
        connector_id = %connector_id,
        revision_count = response.revision_count,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "connector config revision history request complete"
    );
    Ok(Json(response))
}

async fn connector_config_revision_handler(
    State(state): State<Arc<AppState>>,
    Path((connector_id, revision_id)): Path<(String, u64)>,
) -> Result<Json<ConfigRevisionRecord>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "connector_config_revision_request",
        connector_id = %connector_id,
        revision_id,
        "processing connector config revision request"
    );
    let context = load_connector_config_context(&state, &connector_id)
        .await
        .map_err(map_host_error)?;
    let response =
        find_config_revision(&context, &connector_id, revision_id).map_err(map_host_error)?;
    tracing::debug!(
        event = "connector_config_revision_response",
        connector_id = %connector_id,
        revision_id,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "connector config revision request complete"
    );
    Ok(Json(response))
}

async fn connector_config_diff_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    Json(request): Json<ConnectorConfigDiffRequest>,
) -> Result<Json<ConnectorConfigDiffResponse>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "connector_config_diff_request",
        connector_id = %connector_id,
        revision_id = ?request.revision_id,
        "processing connector config diff request"
    );
    let context = load_connector_config_context(&state, &connector_id)
        .await
        .map_err(map_host_error)?;
    let (base_revision_id, base, base_payload) = if let Some(revision_id) = request.revision_id {
        let revision =
            find_config_revision(&context, &connector_id, revision_id).map_err(map_host_error)?;
        (
            Some(revision_id),
            SanitizedConnectorConfig::from(&revision),
            revision.payload,
        )
    } else {
        (
            match current_config_snapshot_source(&context) {
                ConnectorConfigSnapshotSource::ActiveRevision => {
                    current_config_revision_id(&context)
                }
                ConnectorConfigSnapshotSource::ManagedInventory => None,
            },
            context.current.clone(),
            context.raw_payload.clone(),
        )
    };
    let candidate = SanitizedConnectorConfig::from_payload(request.payload.clone())
        .map_err(map_lifecycle_host_error)
        .map_err(map_host_error)?;
    let entries = diff_sanitized_config_values(&base_payload, &request.payload)
        .map_err(map_lifecycle_host_error)
        .map_err(map_host_error)?;
    let response = ConnectorConfigDiffResponse {
        connector_id: connector_id.clone(),
        base_revision_id,
        base,
        candidate,
        changed: !entries.is_empty(),
        entries,
    };
    tracing::debug!(
        event = "connector_config_diff_response",
        connector_id = %connector_id,
        changed = response.changed,
        entry_count = response.entries.len(),
        duration_ms = started_at.elapsed().as_millis() as u64,
        "connector config diff request complete"
    );
    Ok(Json(response))
}

async fn connector_config_validate_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    Json(request): Json<ConnectorConfigValidateRequest>,
) -> Result<Json<ConnectorConfigValidateResponse>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "connector_config_validate_request",
        connector_id = %connector_id,
        "processing connector config validation request"
    );
    let context = load_connector_config_context(&state, &connector_id)
        .await
        .map_err(map_host_error)?;
    ensure_expected_config_revision(
        &connector_id,
        request.expected_active_revision_id,
        current_config_revision_id(&context),
    )
    .map_err(map_host_error)?;
    let candidate = SanitizedConnectorConfig::from_payload(request.payload.clone())
        .map_err(map_lifecycle_host_error)
        .map_err(map_host_error)?;
    let diff = diff_sanitized_config_values(&context.raw_payload, &request.payload)
        .map_err(map_lifecycle_host_error)
        .map_err(map_host_error)?;
    let preview_inventory = next_inventory_with_config(
        state.registry.inventory().await,
        &connector_id,
        request.payload,
    )
    .map_err(map_host_error)?;
    let (valid, preview, error) = match state.registry.preview_configs(preview_inventory).await {
        Ok(preview) => (true, Some(preview), None),
        Err(err) => (false, None, Some(err.to_string())),
    };
    let response = ConnectorConfigValidateResponse {
        connector_id: connector_id.clone(),
        valid,
        current_active_revision_id: current_config_revision_id(&context),
        current: context.current,
        candidate,
        diff,
        preview,
        error,
    };
    tracing::debug!(
        event = "connector_config_validate_response",
        connector_id = %connector_id,
        valid,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "connector config validation request complete"
    );
    Ok(Json(response))
}

async fn connector_config_apply_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    Json(request): Json<ConnectorConfigApplyRequest>,
) -> Result<Json<ConnectorConfigApplyResponse>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "connector_config_apply_request",
        connector_id = %connector_id,
        "processing connector config apply request"
    );
    let response = apply_connector_config_payload(
        &state,
        &connector_id,
        request.payload,
        request.expected_active_revision_id,
        request.created_by,
        request.change_reason,
    )
    .await
    .map_err(map_host_error)?;
    tracing::info!(
        event = "connector_config_apply_response",
        connector_id = %connector_id,
        changed = response.changed,
        current_active_revision_id = ?response.current_active_revision_id,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "connector config apply request complete"
    );
    Ok(Json(response))
}

async fn connector_config_rollback_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    Json(request): Json<ConnectorConfigRollbackRequest>,
) -> Result<Json<ConnectorConfigApplyResponse>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "connector_config_rollback_request",
        connector_id = %connector_id,
        revision_id = request.revision_id,
        "processing connector config rollback request"
    );
    let context = load_connector_config_context(&state, &connector_id)
        .await
        .map_err(map_host_error)?;
    let revision = find_config_revision(&context, &connector_id, request.revision_id)
        .map_err(map_host_error)?;
    if !revision.is_replayable() {
        return Err(map_host_error(HostError::InvalidFilter(format!(
            "config revision '{}' for connector '{}' contains redacted inline secrets and cannot be replayed safely",
            request.revision_id, connector_id
        ))));
    }
    let response = apply_connector_config_payload(
        &state,
        &connector_id,
        revision.payload.clone(),
        request.expected_active_revision_id,
        request.created_by,
        request.change_reason.or_else(|| {
            Some(format!(
                "rollback to config revision {}",
                request.revision_id
            ))
        }),
    )
    .await
    .map_err(map_host_error)?;
    tracing::info!(
        event = "connector_config_rollback_response",
        connector_id = %connector_id,
        revision_id = request.revision_id,
        current_active_revision_id = ?response.current_active_revision_id,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "connector config rollback request complete"
    );
    Ok(Json(response))
}

async fn preflight_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<HostPreflightRequest>,
) -> Json<PreflightResponse> {
    let connector_id = request.connector_id.clone();
    let operation = request.operation.clone();
    let asserted_principal =
        extract_principal_header(&headers).or_else(|| request.principal.clone());
    let started_at = Instant::now();
    let response = match invoke_request_from_preflight(&request) {
        Ok(invoke_request) => {
            evaluate_live_preflight(&state, &invoke_request, asserted_principal.as_deref()).await
        }
        Err(error) => preflight_response_from_error(error),
    };
    tracing::info!(
        event = "preflight_check",
        connector_id = %connector_id,
        operation = %operation,
        asserted_principal = asserted_principal.as_deref(),
        allowed = response.allowed,
        reason = ?response.reason,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "preflight request complete"
    );
    Json(response)
}

async fn simulate_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<HostSimulateRequest>,
) -> Result<Json<HostSimulateResponse>, (StatusCode, String)> {
    let connector_id = request.connector_id.clone();
    let operation = request.operation.clone();
    let request_id = request.request_id.clone();
    let asserted_principal =
        extract_principal_header(&headers).or_else(|| request.principal.clone());
    let started_at = Instant::now();

    tracing::debug!(
        event = "simulate_request",
        connector_id = %connector_id,
        operation = %operation,
        request_id = %request_id,
        asserted_principal = asserted_principal.as_deref(),
        estimate_cost = request.estimate_cost,
        check_availability = request.check_availability,
        deadline_ms = request.deadline_ms,
        "processing simulate request"
    );

    let preflight_request = match invoke_request_from_simulate(&request) {
        Ok(preflight_request) => preflight_request,
        Err(error) => {
            let input = request.input.clone().unwrap_or(serde_json::Value::Null);
            let duration_ms = elapsed_millis(started_at);
            let response = HostSimulateResponse {
                request_id: request_id.clone(),
                would_succeed: false,
                phase: SimulatePhase::PreflightOnly,
                preflight_allowed: false,
                failure_reason: Some(error.to_string()),
                denial_code: None,
                missing_capabilities: Vec::new(),
                cost_estimate: None,
                availability: None,
                duration_ms,
                receipt: simulate_receipt_for_request(
                    &request,
                    &input,
                    SimulatePhase::PreflightOnly,
                    false,
                    duration_ms,
                )
                .map_err(map_host_error)?,
            };
            record_simulate_receipt_summary(state.lifecycle.as_ref(), &response.receipt).await;
            tracing::info!(
                event = "simulate_response",
                connector_id = %connector_id,
                operation = %operation,
                request_id = %request_id,
                phase = ?response.phase,
                preflight_allowed = response.preflight_allowed,
                would_succeed = response.would_succeed,
                receipt_id = %response.receipt.receipt_id,
                duration_ms = response.duration_ms,
                "simulate request complete"
            );
            return Ok(Json(response));
        }
    };

    let preflight =
        evaluate_live_preflight(&state, &preflight_request, asserted_principal.as_deref()).await;
    if !preflight.allowed {
        let input = request.input.clone().unwrap_or(serde_json::Value::Null);
        let duration_ms = elapsed_millis(started_at);
        let response = HostSimulateResponse {
            request_id: request_id.clone(),
            would_succeed: false,
            phase: SimulatePhase::PreflightOnly,
            preflight_allowed: false,
            failure_reason: Some(
                preflight
                    .reason
                    .unwrap_or_else(|| "preflight denied live simulate request".to_string()),
            ),
            denial_code: None,
            missing_capabilities: Vec::new(),
            cost_estimate: None,
            availability: None,
            duration_ms,
            receipt: simulate_receipt_for_request(
                &request,
                &input,
                SimulatePhase::PreflightOnly,
                false,
                duration_ms,
            )
            .map_err(map_host_error)?,
        };
        record_simulate_receipt_summary(state.lifecycle.as_ref(), &response.receipt).await;
        tracing::info!(
            event = "simulate_response",
            connector_id = %connector_id,
            operation = %operation,
            request_id = %request_id,
            phase = ?response.phase,
            preflight_allowed = response.preflight_allowed,
            would_succeed = response.would_succeed,
            receipt_id = %response.receipt.receipt_id,
            duration_ms = response.duration_ms,
            "simulate request complete"
        );
        return Ok(Json(response));
    }

    let simulate_request = simulate_request_from_host(&request).map_err(map_host_error)?;
    let simulate_input = simulate_request.input.clone();
    let simulate_result = fcp_async_core::time::timeout(
        Duration::from_millis(request.deadline_ms),
        state.registry.simulate(simulate_request),
    )
    .await;
    let duration_ms = elapsed_millis(started_at);

    let response = match simulate_result {
        Ok(Ok(simulate_response)) => HostSimulateResponse {
            request_id: request_id.clone(),
            would_succeed: simulate_response.would_succeed,
            phase: SimulatePhase::ConnectorReached,
            preflight_allowed: true,
            failure_reason: simulate_response.failure_reason,
            denial_code: simulate_response.denial_code,
            missing_capabilities: simulate_response.missing_capabilities,
            cost_estimate: simulate_response
                .estimated_cost
                .map(map_simulate_cost_estimate),
            availability: simulate_response
                .availability
                .map(map_simulate_resource_availability),
            duration_ms,
            receipt: simulate_receipt_for_request(
                &request,
                &simulate_input,
                SimulatePhase::ConnectorReached,
                simulate_response.would_succeed,
                duration_ms,
            )
            .map_err(map_host_error)?,
        },
        Ok(Err(error)) if is_simulate_unsupported(&error) => HostSimulateResponse {
            request_id: request_id.clone(),
            would_succeed: false,
            phase: SimulatePhase::ConnectorUnsupported,
            preflight_allowed: true,
            failure_reason: Some(
                "connector does not support simulation for this operation".to_string(),
            ),
            denial_code: None,
            missing_capabilities: Vec::new(),
            cost_estimate: None,
            availability: None,
            duration_ms,
            receipt: simulate_receipt_for_request(
                &request,
                &simulate_input,
                SimulatePhase::ConnectorUnsupported,
                false,
                duration_ms,
            )
            .map_err(map_host_error)?,
        },
        Ok(Err(error)) => {
            tracing::warn!(
                event = "simulate_error",
                connector_id = %connector_id,
                operation = %operation,
                request_id = %request_id,
                error = %error,
                duration_ms,
                "simulate request failed"
            );
            return Err(map_host_error(error));
        }
        Err(_) => HostSimulateResponse {
            request_id: request_id.clone(),
            would_succeed: false,
            phase: SimulatePhase::TimedOut,
            preflight_allowed: true,
            failure_reason: Some("simulation deadline exceeded".to_string()),
            denial_code: None,
            missing_capabilities: Vec::new(),
            cost_estimate: None,
            availability: None,
            duration_ms,
            receipt: simulate_receipt_for_request(
                &request,
                &simulate_input,
                SimulatePhase::TimedOut,
                false,
                duration_ms,
            )
            .map_err(map_host_error)?,
        },
    };

    record_simulate_receipt_summary(state.lifecycle.as_ref(), &response.receipt).await;
    tracing::info!(
        event = "simulate_response",
        connector_id = %connector_id,
        operation = %operation,
        request_id = %request_id,
        phase = ?response.phase,
        preflight_allowed = response.preflight_allowed,
        would_succeed = response.would_succeed,
        receipt_id = %response.receipt.receipt_id,
        duration_ms = response.duration_ms,
        "simulate request complete"
    );

    Ok(Json(response))
}

async fn cancel_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CancellationRequest>,
) -> Result<Json<CancellationResponse>, (StatusCode, String)> {
    let operation_id = request.operation_id.clone();
    // br-jdaro: extract the asserted principal from the same header
    // invoke_handler accepts (`X-Principal`). When the tracked operation
    // has an owner, CancellationController::cancel enforces match and
    // returns HostError::PreflightFailed (→ 403) on mismatch. Operations
    // tracked without an owner stay permissive only for legacy/manual
    // controller callers that intentionally opted into ownerless tracking.
    let asserted_principal = extract_principal_header(&headers);
    let started_at = Instant::now();
    tracing::debug!(
        event = "cancel_request",
        operation_id = %operation_id,
        asserted_principal = asserted_principal.as_deref(),
        reason = %request.reason.label(),
        cleanup = ?request.cleanup,
        return_partial = request.return_partial,
        "processing cancellation request"
    );

    let response = state
        .cancellation
        .cancel(&request, asserted_principal.as_deref(), Utc::now())
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

async fn cancel_self_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CancellationRequest>,
) -> Result<Json<CancellationResponse>, (StatusCode, String)> {
    let operation_id = request.operation_id.clone();
    let verified_principal = verified_cancellation_principal(state.as_ref(), &request)
        .await
        .map_err(map_host_error)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "cancel_self_request",
        operation_id = %operation_id,
        principal = %verified_principal,
        reason = %request.reason.label(),
        cleanup = ?request.cleanup,
        return_partial = request.return_partial,
        "processing owner-scoped cancellation request"
    );

    let response = state
        .cancellation
        .cancel(&request, Some(verified_principal.as_str()), Utc::now())
        .map_err(map_host_error)?;

    tracing::info!(
        event = "cancel_self_response",
        operation_id = %operation_id,
        principal = %verified_principal,
        outcome = ?response.outcome,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "owner-scoped cancellation request complete"
    );
    Ok(Json(response))
}

/// Handle POST /invoke.
///
/// Identity binding:
///   - The default capability-based identity model treats the
///     `capability_token` claim set as the request's authoritative
///     principal. Callers that want defense-in-depth — e.g. an
///     upstream proxy that has already authenticated the caller —
///     can set the `X-Principal` header; its value is forwarded as
///     `principal_override` and `verify_live_request` rejects the
///     request if the header does not match the token's subject/
///     principal_id claim.
///   - Absent the header, behavior is unchanged: the token's claim
///     set drives the principal (br-flywheel_connectors-t623k).
async fn invoke_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<InvokeRequest>,
) -> Result<Json<InvokeResponse>, (StatusCode, String)> {
    request.validate_idempotency_key().map_err(|err| {
        map_host_error(HostError::InvalidFilter(format!(
            "invalid invoke request: {err}"
        )))
    })?;

    let connector_id = request.connector_id.clone();
    let operation = request.operation.clone();
    let operation_name = operation.to_string();
    let correlation_id = request
        .correlation_id
        .as_ref()
        .map(std::string::ToString::to_string);
    let operation_id = request.id.to_string();
    let idempotency_key = request.idempotency_key.clone();
    let zone_id = request.zone_id.clone();
    let asserted_principal = extract_principal_header(&headers);
    let started_at = Instant::now();

    tracing::debug!(
        event = "invoke_request",
        connector_id = %connector_id,
        operation = %operation,
        operation_id = %operation_id,
        correlation_id,
        asserted_principal = asserted_principal.as_deref(),
        "processing invoke request"
    );

    // br-mvax3: build an audit context once so every phase append for
    // this request shares zone/actor/connector/operation/correlation.
    let audit_ctx = fcp_host::InvokeAuditContext {
        zone_id: zone_id.to_string(),
        actor: asserted_principal
            .clone()
            .unwrap_or_else(|| "anonymous".to_string()),
        connector_id: connector_id.to_string(),
        operation: operation_name.clone(),
        operation_id: operation_id.clone(),
        correlation_id: correlation_id.clone(),
        occurred_at: u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
        .unwrap_or(0),
    };

    let preflight = evaluate_live_preflight(&state, &request, asserted_principal.as_deref()).await;
    if !preflight.allowed {
        let reason = preflight
            .reason
            .unwrap_or_else(|| "preflight denied invoke request".to_string());
        // br-mvax3: deny path MUST append a hash-linked audit event so
        // the README "every operation produces an audit event" claim is
        // literally true even for denied requests.
        if let Err(err) = state.invoke_audit.append(
            &audit_ctx,
            fcp_host::InvokePhase::PreflightDeny {
                reason: reason.clone(),
            },
        ) {
            tracing::warn!(
                event = "invoke_audit_append_error",
                phase = "deny",
                error = %err,
                "failed to append invoke deny audit event"
            );
        }
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

    // br-mvax3: preflight allow → append hash-linked audit event before
    // dispatch (matches README's End-to-End Request Flow §11).
    if let Err(err) = state
        .invoke_audit
        .append(&audit_ctx, fcp_host::InvokePhase::PreflightAllow)
    {
        tracing::warn!(
            event = "invoke_audit_append_error",
            phase = "allow",
            error = %err,
            "failed to append invoke allow audit event"
        );
    }

    // br-ug5fk: cancellation ownership must follow the verified token
    // principal, not the optional X-Principal override header. The
    // header is only an equality check against the authenticated token
    // subject/principal_id claim; absent it, the request is still
    // authenticated and must not fall back to ownerless cancellation.
    track_verified_cancellation_owner(state.cancellation.as_ref(), &operation_id, &request)
        .map_err(map_host_error)?;
    let invoke_result = state.registry.invoke(request).await;
    state.cancellation.complete(&operation_id);

    match invoke_result {
        Ok(response) => {
            let duration_ms = elapsed_millis(started_at);
            record_invoke_budget_usage(
                state.budget.as_ref(),
                Some(&zone_id),
                &connector_id,
                &operation_name,
                Some(&response),
            )
            .await;
            record_invoke_receipt_summary(
                state.lifecycle.as_ref(),
                connector_id.as_str(),
                &operation_name,
                idempotency_key,
                &response,
                duration_ms,
            )
            .await;
            // br-mvax3: append hash-linked audit event AFTER dispatch.
            // Fires whether or not the connector returned a receipt_id —
            // this is the failure mode the bead called out (the old
            // ReceiptSummary path silently produced zero events for
            // receipt-less connector returns).
            if let Err(err) = state.invoke_audit.append(
                &audit_ctx,
                fcp_host::InvokePhase::DispatchResult {
                    receipt_id: response.receipt_id.as_ref().map(ToString::to_string),
                    success: matches!(response.status, InvokeStatus::Ok),
                    duration_ms,
                },
            ) {
                tracing::warn!(
                    event = "invoke_audit_append_error",
                    phase = "result",
                    error = %err,
                    "failed to append invoke result audit event"
                );
            }
            tracing::info!(
                event = "invoke_response",
                connector_id = %connector_id,
                operation = %operation,
                operation_id = %operation_id,
                correlation_id,
                status = ?response.status,
                duration_ms,
                "invoke request complete"
            );
            Ok(Json(response))
        }
        Err(err) => {
            let duration_ms = started_at.elapsed().as_millis() as u64;
            record_invoke_budget_usage(
                state.budget.as_ref(),
                Some(&zone_id),
                &connector_id,
                &operation_name,
                None,
            )
            .await;
            // br-mvax3: dispatch error path also appends — the invoke
            // chain is exhaustive across all four phases.
            if let Err(audit_err) = state.invoke_audit.append(
                &audit_ctx,
                fcp_host::InvokePhase::DispatchError {
                    error: err.to_string(),
                    duration_ms,
                },
            ) {
                tracing::warn!(
                    event = "invoke_audit_append_error",
                    phase = "error",
                    error = %audit_err,
                    "failed to append invoke error audit event"
                );
            }
            tracing::warn!(
                event = "invoke_error",
                connector_id = %connector_id,
                operation = %operation,
                operation_id = %operation_id,
                correlation_id,
                error = %err,
                duration_ms,
                "invoke request failed"
            );
            Err(map_host_error(err))
        }
    }
}

async fn record_invoke_receipt_summary(
    lifecycle: &HostAdminStateStore,
    connector_id: &str,
    operation: &str,
    idempotency_key: Option<String>,
    response: &InvokeResponse,
    duration_ms: u64,
) {
    let Some(receipt_id) = response.receipt_id.as_ref() else {
        return;
    };

    let summary = ReceiptSummary {
        receipt_id: receipt_id.to_string(),
        connector_id: connector_id.to_owned(),
        operation: operation.to_owned(),
        success: matches!(response.status, InvokeStatus::Ok),
        duration_ms,
        idempotency_key,
        executed_at: Utc::now(),
    };

    if let Err(err) = lifecycle.record_receipt(summary).await {
        tracing::warn!(
            event = "invoke_receipt_persist_error",
            connector_id,
            operation,
            receipt_id = %receipt_id,
            error = %err,
            "failed to persist invoke receipt summary"
        );
    }
}

async fn record_invoke_budget_usage(
    budget: &BudgetPolicyEngine,
    zone_id: Option<&ZoneId>,
    connector_id: &ConnectorId,
    operation: &str,
    response: Option<&InvokeResponse>,
) {
    let Some(zone_id) = zone_id else {
        return;
    };
    let mut metrics = response
        .and_then(|response| response.usage_metrics.clone())
        .unwrap_or_default();
    if !metrics
        .iter()
        .any(|metric| metric.kind == UsageMetricKind::Requests)
    {
        metrics.push(UsageMetric::requests(1));
    }
    let Some(evaluation) = budget.record_usage(zone_id, metrics.as_slice()).await else {
        return;
    };
    match evaluation.action {
        BudgetAction::Allow => {}
        BudgetAction::Warn | BudgetAction::Deny => {
            tracing::warn!(
                event = "invoke_budget_usage_recorded",
                connector_id = %connector_id,
                operation,
                zone_id = %zone_id,
                action = ?evaluation.action,
                "connector invocation usage exceeded configured budget after execution"
            );
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
    principal_override: Option<Arc<str>>,
) -> OperationResult {
    let started_at = Instant::now();
    let request = operation.request;
    let connector_id = request.connector_id.clone();
    let operation_name = request.operation.to_string();
    let idempotency_key = request.idempotency_key.clone();
    let zone_id = request.zone_id.clone();

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

    let preflight = evaluate_live_preflight(&state, &request, principal_override.as_deref()).await;

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
        Ok(response) => {
            let duration_ms = elapsed_millis(started_at);
            record_invoke_budget_usage(
                state.budget.as_ref(),
                Some(&zone_id),
                &connector_id,
                &operation_name,
                Some(&response),
            )
            .await;
            record_invoke_receipt_summary(
                state.lifecycle.as_ref(),
                connector_id.as_str(),
                &operation_name,
                idempotency_key,
                &response,
                duration_ms,
            )
            .await;
            OperationResult {
                id: operation.id,
                status: OperationResultStatus::Success,
                output: Some(
                    serde_json::to_value(&response)
                        .unwrap_or_else(|_| json!({ "status": "serialization_error" })),
                ),
                error: None,
                duration_ms,
            }
        }
        Err(err) => {
            record_invoke_budget_usage(
                state.budget.as_ref(),
                Some(&zone_id),
                &connector_id,
                &operation_name,
                None,
            )
            .await;
            OperationResult {
                id: operation.id,
                status: OperationResultStatus::Error,
                output: None,
                error: Some(batch_error_from_host_error(err)),
                duration_ms: elapsed_millis(started_at),
            }
        }
    }
}

async fn batch_invoke_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<HttpBatchInvokeRequest>,
) -> Result<Json<BatchInvokeResponse>, (StatusCode, String)> {
    let started_at = Instant::now();
    let asserted_principal = extract_principal_header(&headers).map(Arc::<str>::from);
    tracing::debug!(
        event = "batch_invoke_request",
        operation_count = request.operations.len(),
        max_parallelism = request.options.max_parallelism,
        stop_on_first_error = request.options.stop_on_first_error,
        timeout_ms = request.options.timeout_ms,
        asserted_principal = asserted_principal.as_deref(),
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
    let mut results_map: HashMap<String, OperationResult> =
        HashMap::with_capacity(request.operations.len());
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

            let chunk_results = join_all(ready.into_iter().map(|operation| {
                execute_batch_operation(Arc::clone(&state), operation, asserted_principal.clone())
            }))
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
        .await
        .map_err(|e| map_host_error(map_lifecycle_host_error(e)))?;
    let response = pin_state_response(&state.lifecycle, &connector_id).await;
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
    let response = pin_state_response(&state.lifecycle, &connector_id).await;
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
    let removed_version = state
        .lifecycle
        .unpin(&connector_id)
        .await
        .map_err(|e| map_host_error(map_lifecycle_host_error(e)))?;
    let response = pin_state_response(&state.lifecycle, &connector_id).await;
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
    let pinned_version = state.lifecycle.pinned_version(&connector_id).await;
    let effective_pinned = pinned_version.is_some();
    if pinned != effective_pinned {
        tracing::warn!(
            event = "rollout_evaluate_pinned_override",
            connector_id = %connector_id,
            requested_pinned = pinned,
            effective_pinned,
            pinned_version = ?pinned_version,
            "ignoring client-supplied pinned flag in favor of lifecycle state"
        );
    }
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
                state
                    .lifecycle
                    .pin(&connector_id, target_version)
                    .await
                    .map_err(|e| map_host_error(map_lifecycle_host_error(e)))?;
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
        map_host_error(HostError::Unavailable(format!(
            "connector '{connector_id}' has no rollback target for the current rollout state"
        )))
    })?;
    if rollback_target != to_version {
        return Err(map_host_error(HostError::InvalidFilter(format!(
            "requested rollback target '{to_version}' does not match current rollback target '{rollback_target}'"
        ))));
    }

    let rolled_back = state
        .lifecycle
        .rollback(&connector_id, reason)
        .await
        .map_err(|e| map_host_error(map_lifecycle_host_error(e)))?;
    state
        .lifecycle
        .pin(&connector_id, to_version.clone())
        .await
        .map_err(|e| map_host_error(map_lifecycle_host_error(e)))?;

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
    match rollout_status_response(&state.lifecycle, &connector_id).await {
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

// ── Lifecycle transition and journal handlers ──────────────────────────────

async fn lifecycle_transition_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    Json(request): Json<LifecycleTransitionRequest>,
) -> Result<Json<LifecycleTransitionResponse>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    let started_at = Instant::now();
    tracing::debug!(
        event = "lifecycle_transition_request",
        connector_id = %connector_id,
        action = ?request.action,
        dry_run = request.dry_run,
        "processing lifecycle transition request"
    );

    match state
        .lifecycle
        .execute_lifecycle_transition(&connector_id, &request)
        .await
    {
        Ok(response) => {
            tracing::info!(
                event = "lifecycle_transition_response",
                connector_id = %connector_id,
                action = ?request.action,
                dry_run = request.dry_run,
                previous = ?response.previous_desired_state,
                current = ?response.current_desired_state,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "lifecycle transition complete"
            );
            Ok(Json(response))
        }
        Err(err) => {
            let host_error = map_lifecycle_host_error(err);
            tracing::warn!(
                event = "lifecycle_transition_error",
                connector_id = %connector_id,
                action = ?request.action,
                error = %host_error,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "lifecycle transition failed"
            );
            Err(map_host_error(host_error))
        }
    }
}

async fn lifecycle_record_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
) -> Result<Json<ConnectorAdminStatus>, (StatusCode, String)> {
    let connector_id = parse_connector_id(&connector_id)?;
    match state.lifecycle.connector_status(&connector_id).await {
        Ok(status) => Ok(Json(status)),
        Err(err) => Err(map_host_error(map_lifecycle_host_error(err))),
    }
}

async fn journal_query_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<JournalQueryRequest>,
) -> Json<JournalQueryResponse> {
    let started_at = Instant::now();
    tracing::debug!(
        event = "journal_query_request",
        connector_id = ?request.connector_id,
        after_sequence = request.after_sequence,
        limit = request.limit,
        "processing journal query"
    );
    let response = state.lifecycle.query_journal(&request).await;
    tracing::debug!(
        event = "journal_query_response",
        entries = response.entries.len(),
        total = response.total_entries,
        latest_sequence = response.latest_sequence,
        duration_ms = started_at.elapsed().as_millis() as u64,
        "journal query complete"
    );
    Json(response)
}

async fn journal_connector_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
) -> Json<JournalQueryResponse> {
    let request = JournalQueryRequest {
        connector_id: Some(connector_id),
        after_sequence: 0,
        limit: 100,
    };
    Json(state.lifecycle.query_journal(&request).await)
}

// ── Log, event, and receipt handlers ────────────────────────────────────────

async fn log_query_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<LogQueryRequest>,
) -> Json<LogQueryResponse> {
    tracing::debug!(
        event = "log_query_request",
        connector_id = ?request.connector_id,
        min_severity = ?request.min_severity,
        "processing log query"
    );
    Json(state.lifecycle.query_logs(&request).await)
}

async fn receipt_query_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ReceiptQueryRequest>,
) -> Json<ReceiptQueryResponse> {
    tracing::debug!(
        event = "receipt_query_request",
        connector_id = %request.connector_id,
        operation = ?request.operation,
        "processing receipt query"
    );
    Json(state.lifecycle.query_receipts(&request).await)
}

async fn simulate_receipt_query_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SimulateReceiptQueryRequest>,
) -> Json<SimulateReceiptQueryResponse> {
    tracing::debug!(
        event = "simulate_receipt_query_request",
        connector_id = %request.connector_id,
        operation = ?request.operation,
        "processing simulate receipt query"
    );
    Json(state.lifecycle.query_simulate_receipts(&request).await)
}

async fn event_query_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<EventQueryRequest>,
) -> Json<EventQueryResponse> {
    tracing::debug!(
        event = "event_query_request",
        connector_id = ?request.connector_id,
        kind = ?request.kind,
        unacknowledged_only = request.unacknowledged_only,
        "processing event query"
    );
    Json(state.lifecycle.query_events(&request).await)
}

async fn event_acknowledge_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<EventAcknowledgeRequest>,
) -> Json<EventAcknowledgeResponse> {
    tracing::debug!(
        event = "event_acknowledge_request",
        count = request.event_ids.len(),
        "processing event acknowledgement"
    );
    Json(state.lifecycle.acknowledge_events(&request).await)
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
    use fcp_host::{CancelReason, CleanupBehavior};
    use fcp_kernel::{
        AgentHint, BudgetEnforcement, HealthState, IdempotencyClass, LifecycleRecord, OperationId,
        OperationInfo, SelfCheckStatus, TransitionReason, UsageBudgetLimit, UsageBudgetPolicy,
        UsageMetric, UsageMetricKind,
    };
    use fcp_policy::OperationalModelVersion;
    use fcp_prelude::{CapabilityId, RiskLevel};

    fn maybe_compiled_test_connector_binary() -> Option<std::path::PathBuf> {
        if let Some(path) = option_env!("CARGO_BIN_EXE_fcp-test-connector") {
            return Some(std::path::PathBuf::from(path));
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
        candidate.exists().then_some(candidate)
    }

    fn compiled_test_connector_binary() -> std::path::PathBuf {
        maybe_compiled_test_connector_binary().unwrap_or_else(|| {
            panic!("expected compiled fcp-test-connector alongside the current test executable")
        })
    }

    fn subprocess_test_connector_config(connector_id: &str) -> ConnectorConfig {
        ConnectorConfig {
            id: connector_id.to_string(),
            binary: compiled_test_connector_binary().display().to_string(),
            name: Some("Test Connector".to_string()),
            description: Some("Subprocess test connector".to_string()),
            args: Vec::new(),
            env: BTreeMap::from([(
                "FCP_TEST_CONNECTOR_ID".to_string(),
                connector_id.to_string(),
            )]),
            config: Some(json!({})),
            categories: vec!["test".to_string()],
            version: None,
            allowed_zones: Vec::new(),
            allowed_operations: Vec::new(),
            enforce_empty_allow_lists: false,
        }
    }

    #[test]
    fn connector_inventory_update_replaces_empty_fields() {
        let existing = ConnectorConfig {
            id: "fcp.test.replace:utility:1.0.0".to_string(),
            binary: "/old/bin".to_string(),
            name: Some("Old Name".to_string()),
            description: Some("old description".to_string()),
            args: vec!["--old".to_string()],
            env: BTreeMap::from([("OLD_ENV".to_string(), "1".to_string())]),
            config: Some(json!({ "old": true })),
            categories: vec!["old".to_string()],
            version: Some("1.0.0".to_string()),
            allowed_zones: vec!["z:work".to_string()],
            allowed_operations: Vec::new(),
            enforce_empty_allow_lists: false,
        };
        let incoming = ConnectorConfig {
            id: existing.id.clone(),
            binary: "/new/bin".to_string(),
            name: None,
            description: None,
            args: Vec::new(),
            env: BTreeMap::new(),
            config: None,
            categories: Vec::new(),
            version: None,
            allowed_zones: Vec::new(),
            allowed_operations: Vec::new(),
            enforce_empty_allow_lists: false,
        };

        let updated = replace_connector_update(&existing, &incoming);

        assert_eq!(updated.id, existing.id);
        assert_eq!(updated.binary, "/new/bin");
        assert!(updated.name.is_none());
        assert!(updated.description.is_none());
        assert!(updated.args.is_empty());
        assert!(updated.env.is_empty());
        assert!(updated.config.is_none());
        assert!(updated.categories.is_empty());
        assert!(updated.version.is_none());
        assert!(updated.allowed_zones.is_empty());
    }

    fn subprocess_test_connector_config_requiring_handshake(connector_id: &str) -> ConnectorConfig {
        let mut config = subprocess_test_connector_config(connector_id);
        config.env.insert(
            "FCP_TEST_CONNECTOR_REQUIRE_HANDSHAKE".to_string(),
            "1".to_string(),
        );
        config
    }

    fn subprocess_test_connector_config_with_handshake_mode(
        connector_id: &str,
        handshake_mode: &str,
    ) -> ConnectorConfig {
        let mut config = subprocess_test_connector_config_requiring_handshake(connector_id);
        config.env.insert(
            "FCP_TEST_CONNECTOR_HANDSHAKE_MODE".to_string(),
            handshake_mode.to_string(),
        );
        config
    }

    fn dispatcher_test_connector(
        connector_id: &'static str,
        runner_tx: mpsc::Sender<ConnectorRpcRequest>,
        runner_task: JoinHandle<()>,
    ) -> Arc<SubprocessConnector> {
        let connector_id = ConnectorId::from_static(connector_id);
        let connector = Arc::new(SubprocessConnector {
            summary: ConnectorSummary {
                id: connector_id.clone(),
                name: connector_id.to_string(),
                description: None,
                version: semver::Version::new(1, 0, 0),
                categories: Vec::new(),
                tool_count: 0,
                max_safety_tier: SafetyTier::Safe,
                enabled: true,
                health: ConnectorHealth::healthy(),
                last_health_check: None,
            },
            runner_tx,
            _runner_task: runner_task,
            resilience: Arc::new(ResilienceLayer::default()),
            capability_verifying_key: None,
            handshaken_zone: Mutex::new(None),
        });
        connector.resilience.ensure_connector(&connector.summary.id);
        connector
    }

    fn dispatcher_health_result() -> serde_json::Value {
        json!({
            "status": { "state": "ready" },
            "uptime_ms": 0,
        })
    }

    fn dispatcher_registry_with_connector(
        connector_id: &'static str,
        connector: Arc<SubprocessConnector>,
        config: ConnectorConfig,
    ) -> Arc<SubprocessRegistry> {
        let connector_key = ConnectorId::from_static(connector_id);
        let mut connectors = HashMap::new();
        connectors.insert(connector_key, RegistryEntry { config, connector });
        Arc::new(SubprocessRegistry {
            state: Arc::new(RwLock::new(RegistryState { connectors })),
            resilience: Arc::new(ResilienceLayer::default()),
            version: Arc::new(AtomicU64::new(1)),
            capability_verifying_key: None,
            rate_limiters: Arc::new(HostRateLimiterStore::default()),
        })
    }

    fn dispatcher_app_state(
        registry: Arc<SubprocessRegistry>,
        lifecycle: Arc<HostAdminStateStore>,
        capability_verifying_key: Option<Ed25519VerifyingKey>,
        zone_policies: HashMap<ZoneId, ZonePolicyObject>,
    ) -> Arc<AppState> {
        let budget = Arc::new(BudgetPolicyEngine::new());
        let discovery = Arc::new(DiscoveryEndpoint::new(
            Arc::clone(&registry),
            Arc::clone(&budget),
        ));
        Arc::new(AppState {
            registry: Arc::clone(&registry),
            doctor: DoctorService::new(Arc::clone(&registry)),
            budget,
            discovery,
            cancellation: Arc::new(CancellationController::new()),
            lifecycle: Arc::clone(&lifecycle),
            rollout: Arc::new(RolloutController::new(
                Arc::clone(&registry),
                Arc::clone(&lifecycle),
            )),
            supply_chain: Arc::new(SupplyChainGate::default()),
            capability_verifying_key,
            revocation_cascade: Arc::new(RevocationCascadeVerifier::default()),
            hybrid_owner_verifier: None,
            approval_verifying_key: None,
            admin_bearer_token: None,
            connectors_file: None,
            zone_policies: Arc::new(RwLock::new(zone_policies)),
            invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
            started_at: Instant::now(),
        })
    }

    fn dispatcher_introspection(
        operation_id: &'static str,
        capability_id: &str,
        safety_tier: SafetyTier,
    ) -> Introspection {
        dispatcher_introspection_with_input_schema(
            operation_id,
            capability_id,
            safety_tier,
            json!({ "type": "object" }),
        )
    }

    fn dispatcher_introspection_with_input_schema(
        operation_id: &'static str,
        capability_id: &str,
        safety_tier: SafetyTier,
        input_schema: Value,
    ) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static(operation_id),
                summary: format!("{operation_id} summary"),
                description: Some(format!("{operation_id} description")),
                input_schema,
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::new(capability_id).expect("valid capability id"),
                risk_level: RiskLevel::High,
                safety_tier,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "test operation".to_string(),
                    common_mistakes: Vec::new(),
                    examples: Vec::new(),
                    related: Vec::new(),
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            }],
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: None,
        }
    }

    fn constraints_cbor(constraints: &fcp_core::CapabilityConstraints) -> Vec<u8> {
        let mut cbor = Vec::new();
        ciborium::into_writer(constraints, &mut cbor).expect("test constraints should serialize");
        cbor
    }

    fn wildcard_constraints_cbor() -> Vec<u8> {
        constraints_cbor(&fcp_core::CapabilityConstraints {
            resource_allow: vec!["*".to_string()],
            ..Default::default()
        })
    }

    fn test_capability_grants_value(capability_id: &str, operation_id: &str) -> ciborium::Value {
        let grant = fcp_core::CapabilityGrant {
            capability: fcp_core::CapabilityId::new(capability_id)
                .expect("test capability id should be canonical"),
            operation: Some(
                fcp_core::OperationId::new(operation_id)
                    .expect("test operation id should be canonical"),
            ),
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&vec![grant], &mut cbor).expect("test grants should serialize");
        ciborium::from_reader(&cbor[..]).expect("test grants should decode to CBOR value")
    }

    async fn register_test_capability_issuer(
        lifecycle: &HostAdminStateStore,
        signing_key: &fcp_crypto::ed25519::Ed25519SigningKey,
        connector_id: &str,
        capability_id: &str,
        operation_id: &str,
        zone_id: &str,
    ) {
        lifecycle
            .issue_capability_token(
                &fcp_host::CapabilityIssuanceRequest {
                    connector_id: connector_id.to_string(),
                    capability_id: capability_id.to_string(),
                    zone_id: zone_id.to_string(),
                    principal_id: "user:test".to_string(),
                    operations: vec![operation_id.to_string()],
                    ttl_secs: 3600,
                    not_before_delay_secs: None,
                    holder_node: None,
                    max_delegation_depth: 0,
                    resource_allow: Vec::new(),
                    resource_deny: Vec::new(),
                    max_calls: None,
                    max_bytes: None,
                    credential_allow: Vec::new(),
                    dry_run: false,
                },
                signing_key,
            )
            .await
            .expect("register test capability issuer");
    }

    fn test_capability_token(
        signing_key: &fcp_crypto::ed25519::Ed25519SigningKey,
        capability_id: &str,
        operation_id: &str,
        zone_id: &str,
    ) -> fcp_core::CapabilityToken {
        let now = Utc::now();
        let constraints = wildcard_constraints_cbor();
        fcp_core::CapabilityToken::from_raw(
            fcp_crypto::cose::CapabilityTokenBuilder::new()
                .capability_id(capability_id)
                .zone_id(zone_id)
                .principal("user:test")
                .issuer("node:test")
                .audience("*")
                .operations(&[operation_id])
                .validity(now, now + chrono::Duration::hours(1))
                .try_constraints_cbor(&constraints)
                .expect("test constraints CBOR should be valid")
                .sign(signing_key)
                .expect("test capability token should sign"),
        )
    }

    fn test_capability_token_with_constraints(
        signing_key: &fcp_crypto::ed25519::Ed25519SigningKey,
        capability_id: &str,
        operation_id: &str,
        zone_id: &str,
        constraints: &fcp_core::CapabilityConstraints,
    ) -> fcp_core::CapabilityToken {
        let now = Utc::now();
        let constraints = constraints_cbor(constraints);
        fcp_core::CapabilityToken::from_raw(
            fcp_crypto::cose::CapabilityTokenBuilder::new()
                .capability_id(capability_id)
                .zone_id(zone_id)
                .principal("user:test")
                .issuer("node:test")
                .audience("*")
                .operations(&[operation_id])
                .validity(now, now + chrono::Duration::hours(1))
                .try_constraints_cbor(&constraints)
                .expect("test constraints CBOR should be valid")
                .sign(signing_key)
                .expect("test capability token should sign"),
        )
    }

    fn test_capability_token_with_token_id(
        signing_key: &fcp_crypto::ed25519::Ed25519SigningKey,
        capability_id: &str,
        operation_id: &str,
        zone_id: &str,
        _connector_id: &str,
        token_id: &[u8],
    ) -> fcp_core::CapabilityToken {
        let now = Utc::now();
        let constraints = wildcard_constraints_cbor();
        fcp_core::CapabilityToken::from_raw(
            fcp_crypto::cose::CapabilityTokenBuilder::new()
                .capability_id(capability_id)
                .zone_id(zone_id)
                .principal("user:test")
                .audience("*")
                .issuer("host:test")
                .operations(&[operation_id])
                .token_id(token_id)
                .validity(now, now + chrono::Duration::hours(1))
                .try_constraints_cbor(&constraints)
                .expect("test constraints CBOR should be valid")
                .sign(signing_key)
                .expect("test capability token with explicit token id should sign"),
        )
    }

    fn test_capability_token_with_holder_node(
        signing_key: &fcp_crypto::ed25519::Ed25519SigningKey,
        capability_id: &str,
        operation_id: &str,
        zone_id: &str,
        _connector_id: &str,
        holder_node: &str,
    ) -> fcp_core::CapabilityToken {
        let now = Utc::now();
        let constraints = wildcard_constraints_cbor();
        let grants = test_capability_grants_value(capability_id, operation_id);
        let claims = fcp_crypto::cose::CwtClaims::new()
            .issuer("host:test")
            .subject("user:test")
            .principal_id("user:test")
            .audience("*")
            .zone_id(zone_id)
            .capability_id(capability_id)
            .operations(&[operation_id])
            .holder_node(holder_node)
            .not_before(now)
            .expiration(now + chrono::Duration::hours(1))
            .try_constraints_cbor(&constraints)
            .expect("test constraints CBOR should be valid")
            .custom(fcp_crypto::cose::fcp2_claims::GRANTS, grants);
        fcp_core::CapabilityToken::from_raw(
            fcp_crypto::cose::CoseToken::sign(signing_key, &claims)
                .expect("test holder-bound capability token should sign"),
        )
    }

    struct HybridOwnerProductionFixture {
        v3_signing_key: fcp_crypto::ed25519::Ed25519SigningKey,
        v4_signing_key: fcp_crypto::MlDsa65SigningKey,
        v4_verifying_key: MlDsa65VerifyingKeyBytes,
        prior_v3_attestation: Vec<u8>,
        new_v4_attestation: Vec<u8>,
        migration_attestation: OwnerKeyMigrationAttestation,
    }

    impl HybridOwnerProductionFixture {
        fn new() -> Self {
            let v3_signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
            let v4_signing_key =
                fcp_crypto::MlDsa65SigningKey::generate().expect("generate ML-DSA-65 key");
            let v4_verifying_key = evidence_v4_key(&v4_signing_key);
            let prior_v3_attestation = b"host-last-v3-owner-state".to_vec();
            let new_v4_attestation = b"host-first-v4-owner-state".to_vec();
            let now: u64 = Utc::now().timestamp().try_into().unwrap_or(1_800_000_000);
            let migration_transcript = fcp_evidence::OwnerKeyMigrationTranscript::new(
                v3_signing_key.verifying_key().key_id(),
                v4_verifying_key.key_id(),
                blake3_hash(&prior_v3_attestation),
                blake3_hash(&new_v4_attestation),
                11,
                now.saturating_sub(60),
                now.saturating_add(3600),
            );
            let migration_bytes = migration_transcript.signing_bytes();
            let migration_attestation = OwnerKeyMigrationAttestation::new(
                migration_transcript,
                v3_signing_key.sign(&migration_bytes),
                evidence_v4_signature(
                    &v4_signing_key
                        .sign_deterministic(&migration_bytes, b"")
                        .expect("sign migration bridge"),
                ),
            );
            Self {
                v3_signing_key,
                v4_signing_key,
                v4_verifying_key,
                prior_v3_attestation,
                new_v4_attestation,
                migration_attestation,
            }
        }

        fn verifier(&self) -> Arc<HybridOwnerProductionVerifier> {
            Arc::new(HybridOwnerProductionVerifier::new(
                vec![self.v3_signing_key.verifying_key()],
                self.prior_v3_attestation.clone(),
                self.new_v4_attestation.clone(),
                10,
            ))
        }

        fn verifier_with_prior_v3_attestation(
            &self,
            prior_v3_attestation: Vec<u8>,
        ) -> Arc<HybridOwnerProductionVerifier> {
            Arc::new(HybridOwnerProductionVerifier::new(
                vec![self.v3_signing_key.verifying_key()],
                prior_v3_attestation,
                self.new_v4_attestation.clone(),
                10,
            ))
        }

        fn evidence_for_token(
            &self,
            zone_id: &ZoneId,
            token: &fcp_core::CapabilityToken,
        ) -> HybridOwnerInvokeEvidence {
            let payload = token
                .raw()
                .to_cbor()
                .expect("test capability token should serialize");
            let transcript = fcp_evidence::HybridOwnerObjectTranscript::new(
                fcp_evidence::HybridOwnerObjectKind::CapabilityToken,
                zone_id.clone(),
                &payload,
            );
            let signing_bytes = transcript.signing_bytes();
            HybridOwnerInvokeEvidence {
                signatures: HybridOwnerObjectSignatures::new(
                    self.v3_signing_key.sign(&signing_bytes),
                    evidence_v4_signature(
                        &self
                            .v4_signing_key
                            .sign_deterministic(&signing_bytes, b"")
                            .expect("sign hybrid owner object"),
                    ),
                ),
                migration_attestation: self.migration_attestation.clone(),
                v4_verifying_key: self.v4_verifying_key.clone(),
            }
        }
    }

    fn evidence_v4_key(signing_key: &fcp_crypto::MlDsa65SigningKey) -> MlDsa65VerifyingKeyBytes {
        MlDsa65VerifyingKeyBytes::try_from_bytes(signing_key.verifying_key().as_bytes().to_vec())
            .expect("valid evidence ML-DSA-65 key")
    }

    fn evidence_v4_signature(
        signature: &fcp_crypto::owner_key::MlDsa65SignatureBytes,
    ) -> fcp_evidence::MlDsa65SignatureBytes {
        fcp_evidence::MlDsa65SignatureBytes::try_from_bytes(signature.as_bytes().to_vec())
            .expect("valid evidence ML-DSA-65 signature")
    }

    fn hybrid_owner_evidence_tag(evidence: &HybridOwnerInvokeEvidence) -> String {
        let mut bytes = Vec::new();
        ciborium::into_writer(evidence, &mut bytes)
            .expect("test hybrid owner evidence should serialize");
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn blake3_hash(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn failing_admin_state_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let blocker = dir.path().join("admin-state-blocker");
        std::fs::write(&blocker, "block persistence here").expect("write blocker file");
        blocker.join("state.json")
    }

    async fn test_app_state_with_connectors_file(
        configs: Vec<ConnectorConfig>,
        connectors_file: std::path::PathBuf,
        lifecycle: Arc<HostAdminStateStore>,
    ) -> Arc<AppState> {
        write_connector_configs_file(&connectors_file, &configs).expect("write connectors file");
        let registry = Arc::new(
            SubprocessRegistry::from_configs(configs, None)
                .await
                .expect("registry should load"),
        );
        let doctor = DoctorService::new(Arc::clone(&registry));
        let budget = Arc::new(BudgetPolicyEngine::new());
        let discovery = Arc::new(DiscoveryEndpoint::new(
            Arc::clone(&registry),
            Arc::clone(&budget),
        ));
        let rollout = Arc::new(RolloutController::new(
            Arc::clone(&registry),
            Arc::clone(&lifecycle),
        ));
        Arc::new(AppState {
            registry,
            doctor,
            budget,
            discovery,
            cancellation: Arc::new(CancellationController::new()),
            lifecycle,
            rollout,
            supply_chain: Arc::new(SupplyChainGate::default()),
            capability_verifying_key: None,
            revocation_cascade: Arc::new(RevocationCascadeVerifier::default()),
            hybrid_owner_verifier: None,
            approval_verifying_key: None,
            admin_bearer_token: None,
            connectors_file: Some(connectors_file),
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
            started_at: Instant::now(),
        })
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn verify_live_request_rejects_token_revoked_in_host_state() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping revoked live token test");
            return;
        }

        let connector_id = "fcp.test.revoked-live:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let issued = lifecycle
            .issue_capability_token(
                &fcp_host::CapabilityIssuanceRequest {
                    connector_id: connector_id.to_string(),
                    capability_id: "cap.test.echo".to_string(),
                    zone_id: ZoneId::work().to_string(),
                    principal_id: "user:test".to_string(),
                    operations: vec!["test.echo".to_string()],
                    ttl_secs: 3600,
                    not_before_delay_secs: None,
                    holder_node: None,
                    max_delegation_depth: 0,
                    resource_allow: Vec::new(),
                    resource_deny: Vec::new(),
                    max_calls: None,
                    max_bytes: None,
                    credential_allow: Vec::new(),
                    dry_run: false,
                },
                &signing_key,
            )
            .await
            .expect("issue token for revocation ledger");
        lifecycle
            .revoke_token(&fcp_host::TokenRevocationRequest {
                token_id: issued.token_id.clone(),
                reason: Some("test revocation".to_string()),
            })
            .await
            .expect("revoke token");

        let token_id = hex::decode(&issued.token_id).expect("issued token id should be hex");
        let revoked_live_token = test_capability_token_with_token_id(
            &signing_key,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
            connector_id,
            &token_id,
        );

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![subprocess_test_connector_config(connector_id)],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "revoked token should fail" }),
            capability_token: revoked_live_token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("revoked token should be rejected before live execution");
        assert!(error.to_string().contains("host state"));
        assert!(error.to_string().contains("revoked"));
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn verify_live_request_rejects_zone_outside_connector_binding() {
        // br-flywheel_connectors-by4vu: a structurally-valid capability
        // token signed for zone Z must NOT let a request reach a connector
        // whose `allowed_zones` does not include Z. Before this guard, the
        // gateway looked the connector up by id only and let the request
        // through as long as the token's zone matched the request's zone
        // — completely ignoring whether the operator had bound the
        // connector to that zone.
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping zone-binding test");
            return;
        }

        let connector_id = "fcp.test.zone-binding:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();

        let mut config = subprocess_test_connector_config(connector_id);
        config.allowed_zones = vec![ZoneId::work().as_str().to_string()];

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![config],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        // Token issued for z:secure (different from the connector's
        // allowed_zones). Without the binding check this slips past:
        // verifier binds itself to z:secure, token's zone claim matches.
        let cross_zone_token =
            test_capability_token(&signing_key, "cap.test.echo", "test.echo", "z:secure");

        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::try_from("z:secure".to_string()).expect("zone id"),
            input: json!({ "message": "cross-zone attempt" }),
            capability_token: cross_zone_token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("z:secure request to z:work-only connector must be rejected");
        let msg = error.to_string();
        assert!(
            msg.contains("not bound to zone") && msg.contains("z:secure"),
            "expected zone-binding rejection naming `z:secure`, got: {msg}"
        );
    }

    /// br-ike8x: when the operator has pinned a non-empty
    /// `allowed_operations` list on a connector, the host gateway
    /// MUST reject any InvokeRequest whose `operation` is not in
    /// that list — even if the connector's runtime introspection
    /// would otherwise expose the operation and the capability
    /// token's `capability` claim matches what the connector
    /// self-reports. Closes the manifest-allowed-operations
    /// enforcement gap.
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn verify_live_request_rejects_operation_outside_pinned_allowed_operations() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping allowed_operations test");
            return;
        }

        let connector_id = "fcp.test.op-binding:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();

        let mut config = subprocess_test_connector_config(connector_id);
        // Operator pins ONLY `test.other` as an allowed operation —
        // `test.echo` (which the connector's introspection does
        // expose) is intentionally absent from the pin set.
        config.allowed_operations = vec!["test.other".to_string()];

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![config],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        // Token + request target `test.echo`, which the connector
        // exposes but the operator did not pin. Without the
        // allowed_operations gate this slipped through because the
        // pre-existing introspection check at verify_live_request
        // would find `test.echo` in the connector's tools list.
        let token = test_capability_token(
            &signing_key,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        );
        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "outside-pin attempt" }),
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("op outside pinned allowed_operations must be rejected");
        let msg = error.to_string();
        assert!(
            msg.contains("does not allow operation") && msg.contains("test.echo"),
            "expected op-binding rejection naming `test.echo`, got: {msg}"
        );
        // Defense-in-depth assertion: rejection happens BEFORE the
        // introspection lookup, so the error mentions the
        // operation's display string and the allowed list rather
        // than the connector's introspection findings.
        assert!(
            msg.contains("test.other"),
            "rejection must surface the configured allowed list: {msg}"
        );
    }

    /// br-ike8x defense-in-depth: when allowed_operations is empty
    /// (the back-compat default), the gate must fall through to the
    /// pre-existing introspection-based check. This locks in the
    /// "empty = permissive" semantic — same shape as allowed_zones.
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn verify_live_request_empty_allowed_operations_falls_through() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!(
                "compiled fcp-test-connector missing; skipping allowed_operations fallthrough test"
            );
            return;
        }

        let connector_id = "fcp.test.op-fallthrough:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();

        // Default config: allowed_operations stays empty.
        let config = subprocess_test_connector_config(connector_id);
        assert!(
            config.allowed_operations.is_empty(),
            "test fixture must use the back-compat empty-allowed_operations path"
        );

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![config],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        let token = test_capability_token(
            &signing_key,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        );
        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "fallthrough" }),
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        // Empty allowed_operations does NOT raise an
        // operation-binding error — the request proceeds to the
        // introspection check (which finds `test.echo` and accepts
        // the token).
        let outcome = verify_live_request(state.as_ref(), &request, None).await;
        match outcome {
            Ok(_) => {}
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    !msg.contains("does not allow operation"),
                    "empty allowed_operations must not trigger op-binding rejection: {msg}"
                );
            }
        }
    }

    /// br-v2kt4: explicit fail-closed for empty allowed_zones when
    /// the operator opts in. Pre-fix, an empty allowed_zones list was
    /// always treated as permissive ("no restriction"), so the
    /// security ergonomics were inverted: a misconfigured operator
    /// got the LEAST restrictive behaviour. With
    /// enforce_empty_allow_lists=true, an empty list now means
    /// deny-all.
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn verify_live_request_v2kt4_empty_allowed_zones_with_enforce_flag_denies_all() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping v2kt4 zone deny-all test");
            return;
        }

        let connector_id = "fcp.test.v2kt4-empty-zones-deny:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();

        let mut config = subprocess_test_connector_config(connector_id);
        // Empty allowed_zones + enforce flag = deny-all.
        assert!(config.allowed_zones.is_empty(), "test fixture starts empty");
        config.enforce_empty_allow_lists = true;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![config],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        let token = test_capability_token(
            &signing_key,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        );
        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "v2kt4 deny-all attempt" }),
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("v2kt4: empty allowed_zones + enforce flag must deny-all");
        let msg = error.to_string();
        assert!(
            msg.contains("no `allowed_zones`")
                && msg.contains("enforce_empty_allow_lists=true")
                && msg.contains("br-v2kt4"),
            "expected v2kt4 zone deny-all rejection naming the flag, got: {msg}"
        );
    }

    /// br-v2kt4: same fail-closed shape for empty allowed_operations.
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn verify_live_request_v2kt4_empty_allowed_operations_with_enforce_flag_denies_all() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping v2kt4 op deny-all test");
            return;
        }

        let connector_id = "fcp.test.v2kt4-empty-ops-deny:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();

        let mut config = subprocess_test_connector_config(connector_id);
        // allowed_zones populated so we don't hit the zone gate first.
        config.allowed_zones = vec![ZoneId::work().as_str().to_string()];
        assert!(config.allowed_operations.is_empty(), "test fixture starts empty");
        config.enforce_empty_allow_lists = true;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![config],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        let token = test_capability_token(
            &signing_key,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        );
        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "v2kt4 op deny-all attempt" }),
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("v2kt4: empty allowed_operations + enforce flag must deny-all");
        let msg = error.to_string();
        assert!(
            msg.contains("no `allowed_operations`")
                && msg.contains("enforce_empty_allow_lists=true")
                && msg.contains("br-v2kt4"),
            "expected v2kt4 op deny-all rejection naming the flag, got: {msg}"
        );
    }

    /// br-v2kt4 back-compat: with the flag at its default `false`,
    /// empty allowed_zones / allowed_operations preserve the legacy
    /// permissive path. Ensures the explicit-deny mechanism is opt-in
    /// only — existing deployments that don't set the flag see no
    /// behaviour change.
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn verify_live_request_v2kt4_default_flag_preserves_legacy_permissive_path() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping v2kt4 back-compat test");
            return;
        }

        let connector_id = "fcp.test.v2kt4-default-permissive:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();

        let config = subprocess_test_connector_config(connector_id);
        // Default config: empty allow-lists, enforce_empty_allow_lists=false.
        assert!(config.allowed_zones.is_empty());
        assert!(config.allowed_operations.is_empty());
        assert!(!config.enforce_empty_allow_lists, "default must be false");

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![config],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        let token = test_capability_token(
            &signing_key,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        );
        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "v2kt4 back-compat permissive" }),
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let outcome = verify_live_request(state.as_ref(), &request, None).await;
        // Either succeeds OR fails for some OTHER reason — just must NOT
        // fail with the v2kt4 deny-all message (the back-compat permissive
        // path must keep flowing through to the downstream introspection
        // check, same as pre-v2kt4 behaviour).
        if let Err(err) = outcome {
            let msg = err.to_string();
            assert!(
                !msg.contains("br-v2kt4"),
                "v2kt4 deny-all must NOT fire when flag is at default false: {msg}"
            );
        }
    }

    /// br-l9tt6 (P2 review-mode): the v2kt4 fail-closed gates used to
    /// take TWO separate `state.read().await` acquisitions per request
    /// (one for the allow-list snapshot, one for the
    /// `enforce_empty_allow_lists` flag). A concurrent admin writer
    /// holding the registry write lock between those reads could let a
    /// request decide against a STALE allow-list mixed with a FRESH
    /// flag — producing the inconsistent pairs
    /// `(allowed_zones=['z:work'], enforce_empty=true)` (deny-all
    /// silently bypassed when zone matches) or
    /// `(allowed_zones=[], enforce_empty=false)` (would-be permissive
    /// path observed even though operator just clamped to deny-all).
    ///
    /// This regression races a writer that strictly alternates the
    /// connector entry between two CONSISTENT states against many
    /// concurrent reader calls into `allow_list_snapshot` and asserts
    /// every observed snapshot is one of the two consistent states —
    /// never the inconsistent mix the old two-read pattern allowed.
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn br_l9tt6_allow_list_snapshot_is_atomic_under_concurrent_admin_writer() {
        let connector_id = "fcp.test.l9tt6-snapshot-race:utility:1.0.0";
        let connector_key = ConnectorId::from_static(connector_id);

        // No-op runner: drains rpc requests so the channel doesn't fill.
        // The test never invokes the connector — only `allow_list_snapshot`,
        // which reads `entry.config` under the registry read-lock.
        let (runner_tx, mut runner_rx) = mpsc::channel::<ConnectorRpcRequest>(8);
        let runner_task = task::spawn(async move {
            while let Some(req) = runner_rx.recv().await {
                let _ = req.response_tx.send(Ok(json!({})));
            }
        });
        let connector = dispatcher_test_connector(connector_id, runner_tx, runner_task);

        // State A: legacy permissive — non-empty allow lists, enforce=false.
        let initial_config = ConnectorConfig {
            id: connector_id.to_string(),
            binary: "dispatcher-test".to_string(),
            name: Some("l9tt6 snapshot race fixture".to_string()),
            description: None,
            args: Vec::new(),
            env: BTreeMap::new(),
            config: None,
            categories: vec!["test".to_string()],
            version: None,
            allowed_zones: vec!["z:work".to_string()],
            allowed_operations: vec!["op.a".to_string()],
            enforce_empty_allow_lists: false,
        };
        let registry =
            dispatcher_registry_with_connector(connector_id, connector, initial_config);

        // Writer: strictly alternates the connector entry between
        // State A (['z:work'], ['op.a'], false) and State B ([], [], true).
        // Each write happens under the registry write-lock, so a
        // correctly-atomic reader can ONLY observe one of these two
        // generations.
        let writer_registry = Arc::clone(&registry);
        let writer_key = connector_key.clone();
        const ITERATIONS: usize = 2_000;
        let writer = task::spawn(async move {
            for i in 0..ITERATIONS {
                let mut guard = writer_registry.state.write().await;
                if let Some(entry) = guard.connectors.get_mut(&writer_key) {
                    if i % 2 == 0 {
                        // State B: clamp to deny-all.
                        entry.config.allowed_zones.clear();
                        entry.config.allowed_operations.clear();
                        entry.config.enforce_empty_allow_lists = true;
                    } else {
                        // State A: legacy permissive.
                        entry.config.allowed_zones = vec!["z:work".to_string()];
                        entry.config.allowed_operations = vec!["op.a".to_string()];
                        entry.config.enforce_empty_allow_lists = false;
                    }
                }
                drop(guard);
                // Yield so readers can interleave between writes.
                fcp_async_core::task::yield_now().await;
            }
        });

        // Spawn several concurrent reader tasks. Each captures a
        // snapshot many times. Every snapshot MUST be either State A
        // or State B — never a mix.
        const READERS: usize = 4;
        const READS_PER_READER: usize = 2_000;
        let mut readers = Vec::with_capacity(READERS);
        for _ in 0..READERS {
            let r = Arc::clone(&registry);
            let key = connector_key.clone();
            readers.push(task::spawn(async move {
                let mut inconsistent_observations = 0_usize;
                for _ in 0..READS_PER_READER {
                    let snapshot = r
                        .allow_list_snapshot(&key)
                        .await
                        .expect("connector entry exists");
                    let state_a = !snapshot.allowed_zones.is_empty()
                        && !snapshot.allowed_operations.is_empty()
                        && !snapshot.enforce_empty_allow_lists;
                    let state_b = snapshot.allowed_zones.is_empty()
                        && snapshot.allowed_operations.is_empty()
                        && snapshot.enforce_empty_allow_lists;
                    if !(state_a || state_b) {
                        inconsistent_observations += 1;
                    }
                    fcp_async_core::task::yield_now().await;
                }
                inconsistent_observations
            }));
        }

        writer.await.expect("writer task");
        let mut total_inconsistent = 0_usize;
        for r in readers {
            total_inconsistent += r.await.expect("reader task");
        }

        assert_eq!(
            total_inconsistent, 0,
            "br-l9tt6: allow_list_snapshot returned an inconsistent allow-list / \
             enforce-flag pair under concurrent admin writer — the snapshot must \
             capture all three fields under one read-lock acquisition"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn invoke_handler_hrw_lease_refuses_non_holder_and_admits_elected_holder() {
        let connector_id = "fcp.test.hrw-lease-refuse:utility:1.0.0";
        let operation_id = "test.singleton";
        let capability_id = "cap.test.singleton";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let invoke_count = Arc::new(AtomicU64::new(0));
        let input_schema = json!({
            "type": "object",
            "required": ["lease_seq"],
            "properties": {
                "lease_seq": { "type": "integer" },
                "message": { "type": "string" }
            }
        });

        let introspection = serde_json::to_value(dispatcher_introspection_with_input_schema(
            operation_id,
            capability_id,
            SafetyTier::Safe,
            input_schema,
        ))
        .expect("test introspection should serialize");
        let (runner_tx, mut runner_rx) = mpsc::channel::<ConnectorRpcRequest>(8);
        let runner_invoke_count = Arc::clone(&invoke_count);
        let runner_task = task::spawn(async move {
            while let Some(request) = runner_rx.recv().await {
                match request.method.as_str() {
                    "introspect" => {
                        let _ = request.response_tx.send(Ok(json!({
                            "result": introspection.clone(),
                        })));
                    }
                    "health" => {
                        let _ = request.response_tx.send(Ok(json!({
                            "result": dispatcher_health_result(),
                        })));
                    }
                    "invoke" => {
                        runner_invoke_count.fetch_add(1, Ordering::SeqCst);
                        let invoke_request: InvokeRequest =
                            serde_json::from_value(request.params.clone())
                                .expect("invoke params decode");
                        let _ = request.response_tx.send(Ok(json!({
                            "result": InvokeResponse::ok(
                                invoke_request.id,
                                json!({ "accepted_by_elected_holder": true }),
                            ),
                        })));
                    }
                    method => {
                        let _ = request.response_tx.send(Ok(json!({
                            "error": { "message": format!("unexpected method {method}") },
                        })));
                    }
                }
            }
        });
        let connector = dispatcher_test_connector(connector_id, runner_tx, runner_task);
        let registry = dispatcher_registry_with_connector(
            connector_id,
            connector,
            ConnectorConfig {
                id: connector_id.to_string(),
                binary: "dispatcher-test".to_string(),
                name: Some("HRW Lease Refuse Test Connector".to_string()),
                description: None,
                args: Vec::new(),
                env: BTreeMap::new(),
                config: None,
                categories: vec!["test".to_string()],
                version: None,
                allowed_zones: Vec::new(),
                allowed_operations: Vec::new(),
                enforce_empty_allow_lists: false,
            },
        );
        let state = dispatcher_app_state(
            registry,
            Arc::new(HostAdminStateStore::new()),
            Some(signing_key.verifying_key()),
            HashMap::new(),
        );

        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: ConnectorId::from_static(connector_id),
            operation: OperationId::from_static(operation_id),
            zone_id: ZoneId::work(),
            input: json!({ "message": "non-holder must refuse", "lease_seq": 7 }),
            capability_token: test_capability_token(
                &signing_key,
                capability_id,
                operation_id,
                ZoneId::work().as_str(),
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: Some(7),
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        let subject_id = singleton_writer_lease_subject_id(&request);
        let eligible_nodes = vec![
            TailscaleNodeId::new("node-a"),
            TailscaleNodeId::new("node-b"),
            TailscaleNodeId::new("node-c"),
        ];
        let expected =
            fcp_mesh::planner::select_lease_holder(&request.zone_id, &subject_id, &eligible_nodes)
                .expect("HRW holder selected");
        let local_node = eligible_nodes
            .iter()
            .find(|node| *node != &expected)
            .expect("test set includes non-holder")
            .clone();
        let _guard = set_test_hrw_lease_routing_override(Some(HrwLeaseRoutingConfig {
            local_node: local_node.clone(),
            eligible_nodes: eligible_nodes.clone(),
        }));

        let (status, message) = invoke_handler(
            State(Arc::clone(&state)),
            HeaderMap::new(),
            Json(request.clone()),
        )
        .await
        .expect_err("non-holder singleton_writer invoke must be refused");

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(message.contains("HRW lease routing refused singleton_writer invoke"));
        assert!(message.contains(r#""reason":"wrong_holder""#));
        assert!(message.contains(expected.as_str()));
        assert!(message.contains(local_node.as_str()));
        assert_eq!(
            invoke_count.load(Ordering::SeqCst),
            0,
            "WrongHolder refusal must happen before connector dispatch"
        );
        drop(_guard);
        let mut policies: HashMap<ZoneId, ZonePolicyObject> = HashMap::new();
        policies.insert(ZoneId::work(), host_runtime_policy(ZoneId::work()));
        *state.zone_policies.write().await = policies;
        let _guard = set_test_hrw_lease_routing_override(Some(HrwLeaseRoutingConfig {
            local_node: expected,
            eligible_nodes,
        }));

        let Json(response) = invoke_handler(State(state), HeaderMap::new(), Json(request))
            .await
            .expect("elected holder should dispatch singleton_writer invoke");

        assert_eq!(response.status, InvokeStatus::Ok);
        assert_eq!(
            response.result,
            Some(json!({ "accepted_by_elected_holder": true }))
        );
        assert_eq!(
            invoke_count.load(Ordering::SeqCst),
            1,
            "Elected holder should reach connector dispatch"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn invoke_handler_admit_safety_denies_risky_evaluation_before_dispatch() {
        let connector_id = "fcp.test.admit-safety:utility:1.0.0";
        let operation_id = "test.risky";
        let capability_id = "cap.test.risky";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let invoke_count = Arc::new(AtomicU64::new(0));

        let introspection = serde_json::to_value(dispatcher_introspection(
            operation_id,
            capability_id,
            SafetyTier::Risky,
        ))
        .expect("test introspection should serialize");
        let (runner_tx, mut runner_rx) = mpsc::channel::<ConnectorRpcRequest>(8);
        let runner_invoke_count = Arc::clone(&invoke_count);
        let runner_task = task::spawn(async move {
            while let Some(request) = runner_rx.recv().await {
                match request.method.as_str() {
                    "introspect" => {
                        let _ = request.response_tx.send(Ok(json!({
                            "result": introspection.clone(),
                        })));
                    }
                    "health" => {
                        let _ = request.response_tx.send(Ok(json!({
                            "result": dispatcher_health_result(),
                        })));
                    }
                    "invoke" => {
                        runner_invoke_count.fetch_add(1, Ordering::SeqCst);
                        let _ = request.response_tx.send(Ok(json!({
                            "error": {
                                "message": "admit_safety_tier should deny before dispatch"
                            },
                        })));
                    }
                    method => {
                        let _ = request.response_tx.send(Ok(json!({
                            "error": { "message": format!("unexpected method {method}") },
                        })));
                    }
                }
            }
        });
        let connector = dispatcher_test_connector(connector_id, runner_tx, runner_task);
        let connector_key = ConnectorId::from_static(connector_id);
        let mut connectors = HashMap::new();
        connectors.insert(
            connector_key.clone(),
            RegistryEntry {
                config: ConnectorConfig {
                    id: connector_id.to_string(),
                    binary: "dispatcher-test".to_string(),
                    name: Some("Admit Safety Test Connector".to_string()),
                    description: None,
                    args: Vec::new(),
                    env: BTreeMap::new(),
                    config: None,
                    categories: vec!["test".to_string()],
                    version: None,
                    allowed_zones: Vec::new(),
                    allowed_operations: Vec::new(),
                    enforce_empty_allow_lists: false,
                },
                connector,
            },
        );
        let registry = Arc::new(SubprocessRegistry {
            state: Arc::new(RwLock::new(RegistryState { connectors })),
            resilience: Arc::new(ResilienceLayer::default()),
            version: Arc::new(AtomicU64::new(1)),
            capability_verifying_key: None,
            rate_limiters: Arc::new(HostRateLimiterStore::default()),
        });
        let budget = Arc::new(BudgetPolicyEngine::new());
        let discovery = Arc::new(DiscoveryEndpoint::new(
            Arc::clone(&registry),
            Arc::clone(&budget),
        ));
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let state = Arc::new(AppState {
            registry: Arc::clone(&registry),
            doctor: DoctorService::new(Arc::clone(&registry)),
            budget,
            discovery,
            cancellation: Arc::new(CancellationController::new()),
            lifecycle: Arc::clone(&lifecycle),
            rollout: Arc::new(RolloutController::new(
                Arc::clone(&registry),
                Arc::clone(&lifecycle),
            )),
            supply_chain: Arc::new(SupplyChainGate::default()),
            capability_verifying_key: Some(signing_key.verifying_key()),
            revocation_cascade: Arc::new(RevocationCascadeVerifier::default()),
            hybrid_owner_verifier: None,
            approval_verifying_key: None,
            admin_bearer_token: None,
            connectors_file: None,
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
            started_at: Instant::now(),
        });

        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_key,
            operation: OperationId::from_static(operation_id),
            zone_id: ZoneId::work(),
            input: json!({ "message": "risky operation should be blocked in evaluation" }),
            capability_token: test_capability_token(
                &signing_key,
                capability_id,
                operation_id,
                ZoneId::work().as_str(),
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let (status, message) = invoke_handler(State(state), HeaderMap::new(), Json(request))
            .await
            .expect_err("Risky invoke must be denied in Evaluation before dispatch");

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(message.contains("deployment tier admission denied"));
        assert!(message.contains("tier_requires_mesh_active"));
        assert!(message.contains("insufficient_mesh_quorum"));
        assert_eq!(
            invoke_count.load(Ordering::SeqCst),
            0,
            "DeploymentTier denial must happen before connector dispatch"
        );
    }

    fn invoke_token_bucket_config(operation_id: &str) -> Value {
        let mut operation_pools = serde_json::Map::new();
        operation_pools.insert(operation_id.to_string(), json!(["host.invoke"]));
        json!({
            "rate_limits": {
                "pools": [{
                    "id": "host.invoke",
                    "description": "one invoke per zone",
                    "requests": 1,
                    "window_ms": 60_000,
                    "enforcement": "hard",
                    "scope": "instance"
                }],
                "operation_pools": Value::Object(operation_pools)
            }
        })
    }

    fn invoke_token_bucket_request(
        connector_id: &'static str,
        operation_id: &'static str,
        capability_id: &'static str,
        zone_id: ZoneId,
        signing_key: &fcp_crypto::ed25519::Ed25519SigningKey,
    ) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: ConnectorId::from_static(connector_id),
            operation: OperationId::from_static(operation_id),
            zone_id: zone_id.clone(),
            input: json!({ "message": "rate limited invoke" }),
            capability_token: test_capability_token(
                signing_key,
                capability_id,
                operation_id,
                zone_id.as_str(),
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    fn invoke_token_bucket_state(
        connector_id: &'static str,
        operation_id: &'static str,
        capability_id: &'static str,
        signing_key: &fcp_crypto::ed25519::Ed25519SigningKey,
        invoke_count: Arc<AtomicU64>,
    ) -> Arc<AppState> {
        let introspection = serde_json::to_value(dispatcher_introspection(
            operation_id,
            capability_id,
            SafetyTier::Safe,
        ))
        .expect("test introspection should serialize");
        let (runner_tx, mut runner_rx) = mpsc::channel::<ConnectorRpcRequest>(8);
        let runner_invoke_count = Arc::clone(&invoke_count);
        let runner_task = task::spawn(async move {
            while let Some(request) = runner_rx.recv().await {
                match request.method.as_str() {
                    "introspect" => {
                        let _ = request.response_tx.send(Ok(json!({
                            "result": introspection.clone(),
                        })));
                    }
                    "health" => {
                        let _ = request.response_tx.send(Ok(json!({
                            "result": dispatcher_health_result(),
                        })));
                    }
                    "invoke" => {
                        runner_invoke_count.fetch_add(1, Ordering::SeqCst);
                        let invoke_request: InvokeRequest =
                            serde_json::from_value(request.params.clone())
                                .expect("invoke params decode");
                        let _ = request.response_tx.send(Ok(json!({
                            "result": InvokeResponse::ok(
                                invoke_request.id,
                                json!({ "accepted": true }),
                            ),
                        })));
                    }
                    method => {
                        let _ = request.response_tx.send(Ok(json!({
                            "error": { "message": format!("unexpected method {method}") },
                        })));
                    }
                }
            }
        });
        let connector = dispatcher_test_connector(connector_id, runner_tx, runner_task);
        let registry = dispatcher_registry_with_connector(
            connector_id,
            connector,
            ConnectorConfig {
                id: connector_id.to_string(),
                binary: "dispatcher-test".to_string(),
                name: Some("Invoke Token Bucket Test Connector".to_string()),
                description: None,
                args: Vec::new(),
                env: BTreeMap::new(),
                config: Some(invoke_token_bucket_config(operation_id)),
                categories: vec!["test".to_string()],
                version: None,
                allowed_zones: Vec::new(),
                allowed_operations: Vec::new(),
                enforce_empty_allow_lists: false,
            },
        );
        let mut policies = HashMap::new();
        policies.insert(ZoneId::work(), host_runtime_policy(ZoneId::work()));
        let private_zone = ZoneId::try_from("z:private".to_string()).expect("private zone");
        policies.insert(private_zone.clone(), host_runtime_policy(private_zone));
        dispatcher_app_state(
            registry,
            Arc::new(HostAdminStateStore::new()),
            Some(signing_key.verifying_key()),
            policies,
        )
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn invoke_token_bucket_denies_second_invoke_before_dispatch() {
        let connector_id = "fcp.test.invoke-rate-limit:utility:1.0.0";
        let operation_id = "test.echo";
        let capability_id = "cap.test.echo";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let invoke_count = Arc::new(AtomicU64::new(0));
        let state = invoke_token_bucket_state(
            connector_id,
            operation_id,
            capability_id,
            &signing_key,
            Arc::clone(&invoke_count),
        );

        let first = invoke_token_bucket_request(
            connector_id,
            operation_id,
            capability_id,
            ZoneId::work(),
            &signing_key,
        );
        let _ = invoke_handler(State(Arc::clone(&state)), HeaderMap::new(), Json(first))
            .await
            .expect("first invoke should spend the zone bucket token");

        let second = invoke_token_bucket_request(
            connector_id,
            operation_id,
            capability_id,
            ZoneId::work(),
            &signing_key,
        );
        let (status, message) = invoke_handler(State(state), HeaderMap::new(), Json(second))
            .await
            .expect_err("second same-zone invoke must be rate limited before dispatch");

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            message.contains("rate limit pool `host.invoke` exceeded")
                && message.contains("z:work"),
            "expected host invoke token-bucket denial, got: {message}"
        );
        assert_eq!(
            invoke_count.load(Ordering::SeqCst),
            1,
            "rate-limit denial must happen before connector invoke dispatch"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn invoke_token_bucket_is_partitioned_per_zone() {
        let connector_id = "fcp.test.invoke-rate-limit-zones:utility:1.0.0";
        let operation_id = "test.echo";
        let capability_id = "cap.test.echo";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let invoke_count = Arc::new(AtomicU64::new(0));
        let state = invoke_token_bucket_state(
            connector_id,
            operation_id,
            capability_id,
            &signing_key,
            Arc::clone(&invoke_count),
        );

        let work_request = invoke_token_bucket_request(
            connector_id,
            operation_id,
            capability_id,
            ZoneId::work(),
            &signing_key,
        );
        let _ = invoke_handler(
            State(Arc::clone(&state)),
            HeaderMap::new(),
            Json(work_request),
        )
        .await
        .expect("first work-zone invoke should spend only the work bucket");

        let private_zone = ZoneId::try_from("z:private".to_string()).expect("private zone");
        let private_request = invoke_token_bucket_request(
            connector_id,
            operation_id,
            capability_id,
            private_zone,
            &signing_key,
        );
        let _ = invoke_handler(State(state), HeaderMap::new(), Json(private_request))
            .await
            .expect("same pool in another zone should have an independent bucket");

        assert_eq!(
            invoke_count.load(Ordering::SeqCst),
            2,
            "per-zone buckets must not let one zone consume another zone's token"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn cascade_chain_caller_rejects_revoked_issuer_before_token_validation() {
        let connector_id = "fcp.test.cascade-caller:utility:1.0.0";
        let operation_id = "test.echo";
        let capability_id = "cap.test.echo";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let issuer_kid = signing_key.verifying_key().key_id();
        let node_kid = KeyId::from_bytes([0x23; 8]);
        let owner_kid = KeyId::from_bytes([0x42; 8]);
        let mut chain = AttestationChain::rooted_at(owner_kid.clone());
        chain
            .attest_issuance(issuer_kid.clone(), node_kid.clone())
            .expect("issuer edge");
        chain.attest_node(node_kid, owner_kid).expect("node edge");
        let cascade = RevocationCascadeVerifier::new(CascadeConfig::default())
            .with_chain_for_issuer(issuer_kid.clone(), chain)
            .expect("valid cascade chain")
            .with_hop_revocation(
                issuer_kid,
                CascadeHop::IssuerKey,
                RevocationRecord {
                    revoked_at_unix_ms: 1_700_000_000_000,
                },
            );

        let introspection = serde_json::to_value(dispatcher_introspection(
            operation_id,
            capability_id,
            SafetyTier::Safe,
        ))
        .expect("test introspection should serialize");
        let invoke_count = Arc::new(AtomicU64::new(0));
        let (runner_tx, mut runner_rx) = mpsc::channel::<ConnectorRpcRequest>(8);
        let runner_invoke_count = Arc::clone(&invoke_count);
        let runner_task = task::spawn(async move {
            while let Some(request) = runner_rx.recv().await {
                match request.method.as_str() {
                    "introspect" => {
                        let _ = request.response_tx.send(Ok(json!({
                            "result": introspection.clone(),
                        })));
                    }
                    "invoke" => {
                        runner_invoke_count.fetch_add(1, Ordering::SeqCst);
                        let _ = request.response_tx.send(Ok(json!({
                            "error": {
                                "message": "cascade revocation should deny before dispatch"
                            },
                        })));
                    }
                    method => {
                        let _ = request.response_tx.send(Ok(json!({
                            "error": { "message": format!("unexpected method {method}") },
                        })));
                    }
                }
            }
        });
        let connector = dispatcher_test_connector(connector_id, runner_tx, runner_task);
        let connector_key = ConnectorId::from_static(connector_id);
        let mut connectors = HashMap::new();
        connectors.insert(
            connector_key.clone(),
            RegistryEntry {
                config: ConnectorConfig {
                    id: connector_id.to_string(),
                    binary: "dispatcher-test".to_string(),
                    name: Some("Cascade Caller Test Connector".to_string()),
                    description: None,
                    args: Vec::new(),
                    env: BTreeMap::new(),
                    config: None,
                    categories: vec!["test".to_string()],
                    version: None,
                    allowed_zones: Vec::new(),
                    allowed_operations: Vec::new(),
                    enforce_empty_allow_lists: false,
                },
                connector,
            },
        );
        let registry = Arc::new(SubprocessRegistry {
            state: Arc::new(RwLock::new(RegistryState { connectors })),
            resilience: Arc::new(ResilienceLayer::default()),
            version: Arc::new(AtomicU64::new(1)),
            capability_verifying_key: None,
            rate_limiters: Arc::new(HostRateLimiterStore::default()),
        });
        let budget = Arc::new(BudgetPolicyEngine::new());
        let discovery = Arc::new(DiscoveryEndpoint::new(
            Arc::clone(&registry),
            Arc::clone(&budget),
        ));
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let state = Arc::new(AppState {
            registry: Arc::clone(&registry),
            doctor: DoctorService::new(Arc::clone(&registry)),
            budget,
            discovery,
            cancellation: Arc::new(CancellationController::new()),
            lifecycle: Arc::clone(&lifecycle),
            rollout: Arc::new(RolloutController::new(
                Arc::clone(&registry),
                Arc::clone(&lifecycle),
            )),
            supply_chain: Arc::new(SupplyChainGate::default()),
            capability_verifying_key: Some(signing_key.verifying_key()),
            revocation_cascade: Arc::new(cascade),
            hybrid_owner_verifier: None,
            approval_verifying_key: None,
            admin_bearer_token: None,
            connectors_file: None,
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
            started_at: Instant::now(),
        });
        let token_id = [0x5a; 32];
        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_key,
            operation: OperationId::from_static(operation_id),
            zone_id: ZoneId::work(),
            input: json!({ "message": "revoked issuer should fail cascade" }),
            capability_token: test_capability_token_with_token_id(
                &signing_key,
                capability_id,
                operation_id,
                ZoneId::work().as_str(),
                connector_id,
                &token_id,
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("revoked issuer must reject through cascade walker");
        let message = error.to_string();
        assert!(
            message.contains("revocation cascade") && message.contains("revoked at hop 0"),
            "expected cascade rejection before token validation, got: {message}"
        );
        assert_eq!(
            invoke_count.load(Ordering::SeqCst),
            0,
            "cascade rejection must happen before connector invoke dispatch"
        );
    }

    fn hybrid_owner_context(evidence: &HybridOwnerInvokeEvidence) -> fcp_core::InvokeContext {
        let mut context = fcp_core::InvokeContext::default();
        context.request_tags.insert(
            HYBRID_OWNER_EVIDENCE_TAG.to_string(),
            hybrid_owner_evidence_tag(evidence),
        );
        context
    }

    fn hybrid_owner_production_state(
        connector_id: &'static str,
        capability_id: &'static str,
        operation_id: &'static str,
        signing_key: &fcp_crypto::ed25519::Ed25519SigningKey,
        hybrid_owner_verifier: Arc<HybridOwnerProductionVerifier>,
    ) -> (Arc<AppState>, ConnectorId) {
        let introspection = serde_json::to_value(dispatcher_introspection(
            operation_id,
            capability_id,
            SafetyTier::Safe,
        ))
        .expect("test introspection should serialize");
        let (runner_tx, mut runner_rx) = mpsc::channel::<ConnectorRpcRequest>(8);
        let runner_task = task::spawn(async move {
            while let Some(request) = runner_rx.recv().await {
                match request.method.as_str() {
                    "introspect" => {
                        let _ = request.response_tx.send(Ok(json!({
                            "result": introspection.clone(),
                        })));
                    }
                    "invoke" => {
                        let _ = request.response_tx.send(Ok(json!({
                            "error": {
                                "message": "hybrid owner production test should not dispatch"
                            },
                        })));
                    }
                    method => {
                        let _ = request.response_tx.send(Ok(json!({
                            "error": { "message": format!("unexpected method {method}") },
                        })));
                    }
                }
            }
        });
        let connector = dispatcher_test_connector(connector_id, runner_tx, runner_task);
        let registry = dispatcher_registry_with_connector(
            connector_id,
            connector,
            ConnectorConfig {
                id: connector_id.to_string(),
                binary: "dispatcher-test".to_string(),
                name: Some("Hybrid Owner Production Test Connector".to_string()),
                description: None,
                args: Vec::new(),
                env: BTreeMap::new(),
                config: None,
                categories: vec!["test".to_string()],
                version: None,
                allowed_zones: Vec::new(),
                allowed_operations: Vec::new(),
                enforce_empty_allow_lists: false,
            },
        );
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let mut policies = HashMap::new();
        policies.insert(ZoneId::work(), host_runtime_policy(ZoneId::work()));
        let base_state = dispatcher_app_state(
            registry,
            lifecycle,
            Some(signing_key.verifying_key()),
            policies,
        );
        (
            Arc::new(AppState {
                hybrid_owner_verifier: Some(hybrid_owner_verifier),
                ..(*base_state).clone()
            }),
            ConnectorId::from_static(connector_id),
        )
    }

    fn hybrid_owner_production_request(
        connector_id: ConnectorId,
        operation_id: &'static str,
        zone_id: ZoneId,
        token: fcp_core::CapabilityToken,
        context: Option<fcp_core::InvokeContext>,
    ) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id,
            operation: OperationId::from_static(operation_id),
            zone_id,
            input: json!({ "message": "hybrid owner production authorization" }),
            capability_token: token,
            holder_proof: None,
            context,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn hybrid_owner_production_accepts_valid_capability_evidence() {
        let connector_id = "fcp.test.hybrid-owner-valid:utility:1.0.0";
        let operation_id = "test.echo";
        let capability_id = "cap.test.echo";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let fixture = HybridOwnerProductionFixture::new();
        let (state, connector_key) = hybrid_owner_production_state(
            connector_id,
            capability_id,
            operation_id,
            &signing_key,
            fixture.verifier(),
        );
        let zone_id = ZoneId::work();
        let token =
            test_capability_token(&signing_key, capability_id, operation_id, zone_id.as_str());
        let evidence = fixture.evidence_for_token(&zone_id, &token);
        let request = hybrid_owner_production_request(
            connector_key,
            operation_id,
            zone_id,
            token,
            Some(hybrid_owner_context(&evidence)),
        );

        let verified = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect("valid hybrid owner capability evidence should pass live auth");

        assert_eq!(verified.principal, "user:test");
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn hybrid_owner_production_rejects_missing_evidence_tag() {
        let connector_id = "fcp.test.hybrid-owner-missing:utility:1.0.0";
        let operation_id = "test.echo";
        let capability_id = "cap.test.echo";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let fixture = HybridOwnerProductionFixture::new();
        let (state, connector_key) = hybrid_owner_production_state(
            connector_id,
            capability_id,
            operation_id,
            &signing_key,
            fixture.verifier(),
        );
        let zone_id = ZoneId::work();
        let token =
            test_capability_token(&signing_key, capability_id, operation_id, zone_id.as_str());
        let request =
            hybrid_owner_production_request(connector_key, operation_id, zone_id, token, None);

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("missing hybrid owner evidence must fail closed");
        let message = error.to_string();

        assert!(
            message.contains("missing hybrid owner evidence"),
            "expected missing hybrid evidence rejection, got: {message}"
        );
    }

    /// br-jhbk1: adversarial regression. A request that carries the
    /// hybrid-owner evidence tag MUST be rejected when the host is not
    /// configured with a hybrid-owner verifier
    /// (FCP_HOST_HYBRID_OWNER_CONTEXT_FILE unset). Pre-fix, the silent
    /// `Ok(())` path at verify_live_hybrid_owner_capability allowed the
    /// request through without inspecting the evidence tag — a config-
    /// time auth bypass.
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn hybrid_owner_production_rejects_evidence_tag_when_verifier_unconfigured_jhbk1() {
        let connector_id = "fcp.test.hybrid-owner-no-verifier:utility:1.0.0";
        let operation_id = "test.echo";
        let capability_id = "cap.test.echo";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let fixture = HybridOwnerProductionFixture::new();
        // Build the configured-state, then OVERRIDE hybrid_owner_verifier
        // to None to simulate FCP_HOST_HYBRID_OWNER_CONTEXT_FILE being
        // unset at deployment time.
        let (configured_state, connector_key) = hybrid_owner_production_state(
            connector_id,
            capability_id,
            operation_id,
            &signing_key,
            fixture.verifier(),
        );
        let unconfigured_state = Arc::new(AppState {
            hybrid_owner_verifier: None,
            ..(*configured_state).clone()
        });

        let zone_id = ZoneId::work();
        let token =
            test_capability_token(&signing_key, capability_id, operation_id, zone_id.as_str());
        // Caller asks for hybrid-owner verification by attaching the
        // evidence tag. Pre-fix, the host silently accepted this.
        let evidence = fixture.evidence_for_token(&zone_id, &token);
        let request = hybrid_owner_production_request(
            connector_key,
            operation_id,
            zone_id,
            token,
            Some(hybrid_owner_context(&evidence)),
        );

        let error = verify_live_request(unconfigured_state.as_ref(), &request, None)
            .await
            .expect_err(
                "br-jhbk1: hybrid-owner evidence tag MUST be rejected when verifier is unconfigured",
            );
        let message = error.to_string();
        assert!(
            message.contains("hybrid-owner evidence tag")
                && message.contains("not configured for hybrid-owner verification"),
            "expected jhbk1 unconfigured-verifier rejection naming \
             FCP_HOST_HYBRID_OWNER_CONTEXT_FILE, got: {message}"
        );
        assert!(
            message.contains(HYBRID_OWNER_CONTEXT_FILE_ENV),
            "rejection message must name the env var so operators can fix the config; got: {message}"
        );
    }

    /// br-jhbk1 back-compat: a request that does NOT carry the evidence
    /// tag must still pass the hybrid-owner check when the verifier is
    /// unconfigured (legacy V3-only path). This test pins that the
    /// fail-closed change above does not break the V3 path.
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn hybrid_owner_production_unconfigured_verifier_allows_v3_only_requests_jhbk1() {
        let connector_id = "fcp.test.hybrid-owner-v3-only:utility:1.0.0";
        let operation_id = "test.echo";
        let capability_id = "cap.test.echo";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let fixture = HybridOwnerProductionFixture::new();
        let (configured_state, connector_key) = hybrid_owner_production_state(
            connector_id,
            capability_id,
            operation_id,
            &signing_key,
            fixture.verifier(),
        );
        let unconfigured_state = Arc::new(AppState {
            hybrid_owner_verifier: None,
            ..(*configured_state).clone()
        });

        let zone_id = ZoneId::work();
        let token =
            test_capability_token(&signing_key, capability_id, operation_id, zone_id.as_str());
        // No evidence tag attached → legacy V3-only request shape.
        let request = hybrid_owner_production_request(
            connector_key,
            operation_id,
            zone_id,
            token,
            None,
        );

        let verified = verify_live_request(unconfigured_state.as_ref(), &request, None)
            .await
            .expect(
                "br-jhbk1: V3-only request (no evidence tag) must still pass when verifier is unconfigured",
            );
        assert_eq!(verified.principal, "user:test");
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn hybrid_owner_production_rejects_tampered_v4_counter_signature() {
        let connector_id = "fcp.test.hybrid-owner-tampered-v4:utility:1.0.0";
        let operation_id = "test.echo";
        let capability_id = "cap.test.echo";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let fixture = HybridOwnerProductionFixture::new();
        let (state, connector_key) = hybrid_owner_production_state(
            connector_id,
            capability_id,
            operation_id,
            &signing_key,
            fixture.verifier(),
        );
        let zone_id = ZoneId::work();
        let token =
            test_capability_token(&signing_key, capability_id, operation_id, zone_id.as_str());
        let mut evidence = fixture.evidence_for_token(&zone_id, &token);
        let mut tampered_signature = evidence.signatures.signed_with_v4.as_bytes().to_vec();
        tampered_signature[0] ^= 0x01;
        evidence.signatures.signed_with_v4 =
            fcp_evidence::MlDsa65SignatureBytes::try_from_bytes(tampered_signature)
                .expect("tampered signature keeps valid length");
        let request = hybrid_owner_production_request(
            connector_key,
            operation_id,
            zone_id,
            token,
            Some(hybrid_owner_context(&evidence)),
        );

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("tampered V4 owner counter-signature must fail closed");
        let message = error.to_string();

        assert!(
            message.contains("hybrid owner capability token rejected")
                && message.contains("V4 ML-DSA-65 owner-object signature"),
            "expected V4 hybrid owner signature rejection, got: {message}"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn hybrid_owner_production_rejects_missing_v3_attestation_context() {
        let connector_id = "fcp.test.hybrid-owner-missing-v3:utility:1.0.0";
        let operation_id = "test.echo";
        let capability_id = "cap.test.echo";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let fixture = HybridOwnerProductionFixture::new();
        let (state, connector_key) = hybrid_owner_production_state(
            connector_id,
            capability_id,
            operation_id,
            &signing_key,
            fixture.verifier_with_prior_v3_attestation(b"missing-v3-state".to_vec()),
        );
        let zone_id = ZoneId::work();
        let token =
            test_capability_token(&signing_key, capability_id, operation_id, zone_id.as_str());
        let evidence = fixture.evidence_for_token(&zone_id, &token);
        let request = hybrid_owner_production_request(
            connector_key,
            operation_id,
            zone_id,
            token,
            Some(hybrid_owner_context(&evidence)),
        );

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("missing V3 owner attestation context must fail closed");
        let message = error.to_string();

        assert!(
            message.contains("prior V3 attestation hash mismatch"),
            "expected V3 attestation bridge rejection, got: {message}"
        );
    }

    #[test]
    fn single_host_v2_default_falls_back_to_v1_with_warning() {
        let classification = classify_deployment_mode(MeshQuorumSignals::single_host_evaluation());
        let selection = select_host_operational_model_from_env_values(&classification, None, None);

        assert_eq!(selection.requested, OperationalModelVersion::V2MeshNative);
        assert_eq!(selection.effective, OperationalModelVersion::V1HostFirst);
        assert!(selection.single_host_detected);
        assert!(!selection.degraded_v2_opt_in);
        assert!(
            selection
                .warning
                .is_some_and(|warning| warning.contains("falling back to V1HostFirst"))
        );
    }

    #[test]
    fn single_host_v2_explicit_accept_degraded_keeps_v2() {
        let classification = classify_deployment_mode(MeshQuorumSignals::single_host_evaluation());
        let selection = select_host_operational_model_from_env_values(
            &classification,
            Some("v2"),
            Some("true"),
        );

        assert_eq!(selection.requested, OperationalModelVersion::V2MeshNative);
        assert_eq!(selection.effective, OperationalModelVersion::V2MeshNative);
        assert!(selection.single_host_detected);
        assert!(selection.degraded_v2_opt_in);
        assert_eq!(selection.warning, None);
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn verify_live_request_rejects_capability_constraint_denial() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping constraint-denial test");
            return;
        }

        let connector_id = "fcp.test.constraint-denial:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        register_test_capability_issuer(
            lifecycle.as_ref(),
            &signing_key,
            connector_id,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        )
        .await;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![subprocess_test_connector_config(connector_id)],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;

        let mut policies: HashMap<ZoneId, ZonePolicyObject> = HashMap::new();
        policies.insert(ZoneId::work(), host_runtime_policy(ZoneId::work()));

        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            zone_policies: Arc::new(RwLock::new(policies)),
            ..(*base_state).clone()
        });

        let constraints = fcp_core::CapabilityConstraints {
            resource_allow: vec!["*".to_string()],
            max_calls: Some(0),
            ..Default::default()
        };
        let token = test_capability_token_with_constraints(
            &signing_key,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
            &constraints,
        );
        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "constraint denial should fail before dispatch" }),
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("max_calls=0 capability constraint must reject live execution");
        let msg = error.to_string();
        assert!(
            msg.contains("capability constraint denied") && msg.contains("max_calls"),
            "expected live capability-constraint denial, got: {msg}"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn verify_live_request_rejects_holder_bound_token_without_holder_proof() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping holder-proof test");
            return;
        }

        let connector_id = "fcp.test.holder-bound:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![subprocess_test_connector_config(connector_id)],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "holder-bound token should fail closed" }),
            capability_token: test_capability_token_with_holder_node(
                &signing_key,
                "cap.test.echo",
                "test.echo",
                ZoneId::work().as_str(),
                connector_id,
                "node:laptop",
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("holder-bound token without holder_proof must be rejected");
        let msg = error.to_string();
        assert!(
            msg.contains("holder-bound") && msg.contains("holder_proof"),
            "expected missing holder_proof rejection, got: {msg}"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn verify_live_request_rejects_holder_proof_node_mismatch() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!(
                "compiled fcp-test-connector missing; skipping holder-proof node mismatch test"
            );
            return;
        }

        let connector_id = "fcp.test.holder-node-mismatch:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![subprocess_test_connector_config(connector_id)],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "mismatched holder proof should fail" }),
            capability_token: test_capability_token_with_holder_node(
                &signing_key,
                "cap.test.echo",
                "test.echo",
                ZoneId::work().as_str(),
                connector_id,
                "node:laptop",
            ),
            holder_proof: Some(fcp_core::HolderProof::new(
                [0u8; 64],
                fcp_core::TailscaleNodeId::new("node:desktop"),
            )),
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("holder_proof node mismatch must be rejected");
        let msg = error.to_string();
        assert!(
            msg.contains("holder_proof node") && msg.contains("holder_node"),
            "expected holder-node mismatch rejection, got: {msg}"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn verify_live_request_applies_configured_zone_principal_deny() {
        // br-flywheel_connectors-d4cij: when a zone policy with a populated
        // principal_deny pattern list is registered for the request's zone,
        // simulate_policy_decision must see it and the gate must reject —
        // not silently fall back to the permissive host_runtime_policy.
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping zone-policy-deny test");
            return;
        }

        let connector_id = "fcp.test.zone-policy-deny:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        register_test_capability_issuer(
            lifecycle.as_ref(),
            &signing_key,
            connector_id,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        )
        .await;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![subprocess_test_connector_config(connector_id)],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;

        let mut deny_policy = host_runtime_policy(ZoneId::work());
        deny_policy.principal_deny = vec![fcp_core::PolicyPattern {
            pattern: "user:test".to_string(),
        }];
        let mut policies: HashMap<ZoneId, ZonePolicyObject> = HashMap::new();
        policies.insert(ZoneId::work(), deny_policy);

        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            zone_policies: Arc::new(RwLock::new(policies)),
            ..(*base_state).clone()
        });

        let token = test_capability_token(
            &signing_key,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        );

        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "should be denied by zone policy" }),
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("principal_deny pattern must reject the live request");
        assert!(
            error.to_string().contains("policy denied"),
            "expected policy-deny rejection, got: {error}"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn verify_live_request_rejects_missing_zone_policy() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping missing-zone-policy test");
            return;
        }

        let connector_id = "fcp.test.zone-policy-missing:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        register_test_capability_issuer(
            lifecycle.as_ref(),
            &signing_key,
            connector_id,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        )
        .await;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![subprocess_test_connector_config(connector_id)],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;

        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            ..(*base_state).clone()
        });

        let token = test_capability_token(
            &signing_key,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        );

        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "should be denied without zone policy" }),
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let error = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect_err("missing zone policy must reject the live request");
        assert!(
            error
                .to_string()
                .contains("no zone policy configured for live request zone"),
            "expected missing-zone-policy rejection, got: {error}"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn verify_live_request_accepts_configured_key_when_host_state_lacks_issuer() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!(
                "compiled fcp-test-connector missing; skipping configured-key live token test"
            );
            return;
        }

        let connector_id = "fcp.test.configured-key:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![subprocess_test_connector_config(connector_id)],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;

        let mut policies: HashMap<ZoneId, ZonePolicyObject> = HashMap::new();
        policies.insert(ZoneId::work(), host_runtime_policy(ZoneId::work()));
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            zone_policies: Arc::new(RwLock::new(policies)),
            ..(*base_state).clone()
        });

        let token = test_capability_token(
            &signing_key,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        );
        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "configured key should remain authoritative" }),
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let verified = verify_live_request(state.as_ref(), &request, None)
            .await
            .expect("configured live key should authenticate external tokens");
        assert_eq!(verified.principal, "user:test");
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn evaluate_live_preflight_host_state_rejection_does_not_track_cancellation() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!(
                "compiled fcp-test-connector missing; skipping host-state preflight cleanup test"
            );
            return;
        }

        let connector_id = "fcp.test.revoked-preflight:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let issued = lifecycle
            .issue_capability_token(
                &fcp_host::CapabilityIssuanceRequest {
                    connector_id: connector_id.to_string(),
                    capability_id: "cap.test.echo".to_string(),
                    zone_id: ZoneId::work().to_string(),
                    principal_id: "user:test".to_string(),
                    operations: vec!["test.echo".to_string()],
                    ttl_secs: 3600,
                    not_before_delay_secs: None,
                    holder_node: None,
                    max_delegation_depth: 0,
                    resource_allow: Vec::new(),
                    resource_deny: Vec::new(),
                    max_calls: None,
                    max_bytes: None,
                    credential_allow: Vec::new(),
                    dry_run: false,
                },
                &signing_key,
            )
            .await
            .expect("issue token for revocation ledger");
        lifecycle
            .revoke_token(&fcp_host::TokenRevocationRequest {
                token_id: issued.token_id.clone(),
                reason: Some("test revocation".to_string()),
            })
            .await
            .expect("revoke token");

        let token_id = hex::decode(&issued.token_id).expect("issued token id should be hex");
        let revoked_live_token = test_capability_token_with_token_id(
            &signing_key,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
            connector_id,
            &token_id,
        );

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![subprocess_test_connector_config(connector_id)],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "revoked token should fail" }),
            capability_token: revoked_live_token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let preflight = evaluate_live_preflight(state.as_ref(), &request, None).await;
        assert!(!preflight.allowed);
        assert!(
            preflight
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("capability token rejected by host state"))
        );
        assert!(
            preflight
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("revoked"))
        );
        assert_eq!(state.cancellation.tracked_count(), 0);
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn invoke_handler_propagates_host_state_preflight_rejection() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!(
                "compiled fcp-test-connector missing; skipping host-state invoke propagation test"
            );
            return;
        }

        let connector_id = "fcp.test.revoked-invoke:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let issued = lifecycle
            .issue_capability_token(
                &fcp_host::CapabilityIssuanceRequest {
                    connector_id: connector_id.to_string(),
                    capability_id: "cap.test.echo".to_string(),
                    zone_id: ZoneId::work().to_string(),
                    principal_id: "user:test".to_string(),
                    operations: vec!["test.echo".to_string()],
                    ttl_secs: 3600,
                    not_before_delay_secs: None,
                    holder_node: None,
                    max_delegation_depth: 0,
                    resource_allow: Vec::new(),
                    resource_deny: Vec::new(),
                    max_calls: None,
                    max_bytes: None,
                    credential_allow: Vec::new(),
                    dry_run: false,
                },
                &signing_key,
            )
            .await
            .expect("issue token for revocation ledger");
        lifecycle
            .revoke_token(&fcp_host::TokenRevocationRequest {
                token_id: issued.token_id.clone(),
                reason: Some("test revocation".to_string()),
            })
            .await
            .expect("revoke token");

        let token_id = hex::decode(&issued.token_id).expect("issued token id should be hex");
        let revoked_live_token = test_capability_token_with_token_id(
            &signing_key,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
            connector_id,
            &token_id,
        );

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![subprocess_test_connector_config(connector_id)],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "revoked token should fail" }),
            capability_token: revoked_live_token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let (status, message) = invoke_handler(State(state), HeaderMap::new(), Json(request))
            .await
            .expect_err("invoke handler should surface preflight failure");
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(message.contains("preflight failed"));
        assert!(message.contains("capability token rejected by host state"));
        assert!(message.contains("revoked"));
    }

    #[test]
    fn invoke_handler_uses_verified_principal_for_cancellation_when_header_missing() {
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let request = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: "fcp.test.cancel-owner:utility:1.0.0"
                .parse()
                .expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "cancellation owner should follow token subject" }),
            capability_token: test_capability_token(
                &signing_key,
                "cap.test.echo",
                "test.echo",
                ZoneId::work().as_str(),
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        let operation_id = request.id.to_string();
        let cancellation = CancellationController::new();

        track_verified_cancellation_owner(&cancellation, &operation_id, &request)
            .expect("verified token subject should be tracked as cancellation owner");

        let error = cancellation
            .cancel(
                &CancellationRequest {
                    operation_id,
                    reason: CancelReason::UserRequested,
                    cleanup: CleanupBehavior::default(),
                    return_partial: false,
                    capability_token: None,
                },
                Some("user:other"),
                Utc::now(),
            )
            .expect_err("mismatched principal should not cancel a headerless authenticated invoke");
        assert!(
            error
                .to_string()
                .contains("cancellation principal mismatch"),
            "expected cancellation owner mismatch, got: {error}"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn batch_invoke_handler_rejects_principal_header_mismatch() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!(
                "compiled fcp-test-connector missing; skipping batch principal mismatch test"
            );
            return;
        }

        let connector_id = "fcp.test.batch-principal-mismatch:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        register_test_capability_issuer(
            lifecycle.as_ref(),
            &signing_key,
            connector_id,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        )
        .await;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![subprocess_test_connector_config(connector_id)],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        let request = HttpBatchInvokeRequest {
            operations: vec![HttpBatchOperation {
                id: "op-1".to_string(),
                request: InvokeRequest {
                    r#type: "invoke".to_string(),
                    id: RequestId::random(),
                    connector_id: connector_id.parse().expect("connector id"),
                    operation: OperationId::from_static("test.echo"),
                    zone_id: ZoneId::work(),
                    input: json!({ "message": "principal mismatch should fail" }),
                    capability_token: test_capability_token(
                        &signing_key,
                        "cap.test.echo",
                        "test.echo",
                        ZoneId::work().as_str(),
                    ),
                    holder_proof: None,
                    context: None,
                    idempotency_key: None,
                    lease_seq: None,
                    deadline_ms: None,
                    correlation_id: None,
                    provenance: None,
                    approval_tokens: Vec::new(),
                },
                depends_on: Vec::new(),
            }],
            options: BatchOptions::default(),
        };

        let mut headers = HeaderMap::new();
        headers.insert(PRINCIPAL_HEADER, HeaderValue::from_static("user:other"));

        let response = batch_invoke_handler(State(state), headers, Json(request))
            .await
            .expect("batch handler should return structured result")
            .0;
        assert_eq!(response.failed, 1);
        assert_eq!(response.completed, 0);
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].status, OperationResultStatus::Error);
        assert!(
            response.results[0]
                .error
                .as_ref()
                .is_some_and(|error| error.message.contains("request principal `user:other`")),
            "expected principal mismatch denial, got: {:?}",
            response.results[0].error
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn preflight_handler_rejects_principal_header_mismatch() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!(
                "compiled fcp-test-connector missing; skipping preflight principal mismatch test"
            );
            return;
        }

        let connector_id = "fcp.test.preflight-principal-mismatch:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        register_test_capability_issuer(
            lifecycle.as_ref(),
            &signing_key,
            connector_id,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        )
        .await;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![subprocess_test_connector_config(connector_id)],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        let request = HostPreflightRequest {
            request_id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: "test.echo".to_string(),
            params: Some(json!({ "message": "principal mismatch should fail" })),
            principal: Some("user:test".to_string()),
            zone_id: Some(ZoneId::work()),
            capability_token: Some(test_capability_token(
                &signing_key,
                "cap.test.echo",
                "test.echo",
                ZoneId::work().as_str(),
            )),
            approval_tokens: Vec::new(),
        };

        let mut headers = HeaderMap::new();
        headers.insert(PRINCIPAL_HEADER, HeaderValue::from_static("user:other"));

        let response = preflight_handler(State(state), headers, Json(request))
            .await
            .0;
        assert!(!response.allowed, "{response:?}");
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("request principal `user:other`")),
            "expected principal mismatch denial, got: {:?}",
            response.reason
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn simulate_handler_rejects_principal_header_mismatch() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!(
                "compiled fcp-test-connector missing; skipping simulate principal mismatch test"
            );
            return;
        }

        let connector_id = "fcp.test.simulate-principal-mismatch:utility:1.0.0";
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        register_test_capability_issuer(
            lifecycle.as_ref(),
            &signing_key,
            connector_id,
            "cap.test.echo",
            "test.echo",
            ZoneId::work().as_str(),
        )
        .await;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let connectors_file = tempdir.path().join("connectors.json");
        let base_state = test_app_state_with_connectors_file(
            vec![subprocess_test_connector_config(connector_id)],
            connectors_file,
            Arc::clone(&lifecycle),
        )
        .await;
        let state = Arc::new(AppState {
            capability_verifying_key: Some(signing_key.verifying_key()),
            ..(*base_state).clone()
        });

        let request = HostSimulateRequest {
            request_id: "simulate-principal-mismatch".to_string(),
            connector_id: connector_id.to_string(),
            operation: "test.echo".to_string(),
            input: Some(json!({ "message": "principal mismatch should fail" })),
            zone_id: Some(ZoneId::work().to_string()),
            principal: Some("user:test".to_string()),
            capability_token: Some(test_capability_token(
                &signing_key,
                "cap.test.echo",
                "test.echo",
                ZoneId::work().as_str(),
            )),
            approval_tokens: Vec::new(),
            estimate_cost: false,
            check_availability: false,
            deadline_ms: 5_000,
        };

        let mut headers = HeaderMap::new();
        headers.insert(PRINCIPAL_HEADER, HeaderValue::from_static("user:other"));

        let response = simulate_handler(State(state), headers, Json(request))
            .await
            .expect("simulate handler should return structured denial")
            .0;
        assert!(!response.preflight_allowed, "{response:?}");
        assert!(!response.would_succeed, "{response:?}");
        assert_eq!(response.phase, SimulatePhase::PreflightOnly);
        assert!(
            response
                .failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("request principal `user:other`")),
            "expected principal mismatch denial, got: {:?}",
            response.failure_reason
        );
    }

    fn rollout_handler_test_policy() -> RolloutPolicy {
        RolloutPolicy::builder()
            .canary_percent(5)
            .min_canary_duration_secs(0)
            .success_thresholds(fcp_core::SuccessThresholds::new(0, 10_000, 1, 300))
            .rollback_rules(fcp_core::RollbackRules::new(10_000, 3, 1, 300, true))
            .build()
    }

    fn invoke_response_with_metrics(metrics: Vec<UsageMetric>) -> InvokeResponse {
        InvokeResponse::ok(RequestId::random(), json!({"ok": true})).with_usage_metrics(metrics)
    }

    #[test]
    fn runtime_self_check_failure_report_marks_runtime_errors_as_failed() {
        let report = runtime_self_check_failure_report(&HostError::RegistryError(
            "subprocess exited".into(),
        ));

        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert_eq!(report.reason_code.as_deref(), Some("self_check_runtime"));
        assert!(
            report
                .message
                .as_deref()
                .is_some_and(|message| message.contains("subprocess exited"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn record_invoke_budget_usage_updates_zone_budget_from_response_metrics() {
        let budget = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        let connector_id = ConnectorId::from_static("fcp.test.budget-recording:utility:1.0.0");
        budget
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        record_invoke_budget_usage(
            &budget,
            Some(&zone),
            &connector_id,
            "test.echo",
            Some(&invoke_response_with_metrics(vec![UsageMetric::tokens(60)])),
        )
        .await;

        let snapshot = budget
            .snapshot(&zone)
            .await
            .expect("budget policy should produce a snapshot");
        assert_eq!(snapshot.budgets[0].used, 60);
        assert_eq!(snapshot.budgets[0].remaining, 40);
    }

    #[fcp_async_core::runtime::test]
    async fn record_invoke_budget_usage_ignores_missing_zone_or_metrics() {
        let budget = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        let connector_id = ConnectorId::from_static("fcp.test.budget-noop:utility:1.0.0");
        budget
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        record_invoke_budget_usage(
            &budget,
            None,
            &connector_id,
            "test.echo",
            Some(&invoke_response_with_metrics(vec![UsageMetric::tokens(60)])),
        )
        .await;
        record_invoke_budget_usage(
            &budget,
            Some(&zone),
            &connector_id,
            "test.echo",
            Some(&InvokeResponse::ok(
                RequestId::random(),
                json!({"ok": true}),
            )),
        )
        .await;

        let snapshot = budget
            .snapshot(&zone)
            .await
            .expect("budget policy should produce a snapshot");
        assert_eq!(snapshot.budgets[0].used, 0);
        assert_eq!(snapshot.budgets[0].remaining, 100);
    }

    #[fcp_async_core::runtime::test]
    async fn record_invoke_budget_usage_counts_request_without_connector_metric() {
        let budget = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        let connector_id = ConnectorId::from_static("fcp.test.budget-requests:utility:1.0.0");
        budget
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Requests,
                        limit: 10,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        record_invoke_budget_usage(
            &budget,
            Some(&zone),
            &connector_id,
            "test.echo",
            Some(&InvokeResponse::ok(
                RequestId::random(),
                json!({"ok": true}),
            )),
        )
        .await;

        let snapshot = budget
            .snapshot(&zone)
            .await
            .expect("budget policy should produce a snapshot");
        assert_eq!(snapshot.budgets[0].used, 1);
        assert_eq!(snapshot.budgets[0].remaining, 9);
    }

    #[fcp_async_core::runtime::test]
    async fn record_invoke_budget_usage_counts_failed_invoke_attempt() {
        let budget = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        let connector_id = ConnectorId::from_static("fcp.test.budget-failed-request:utility:1.0.0");
        budget
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Requests,
                        limit: 10,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        record_invoke_budget_usage(&budget, Some(&zone), &connector_id, "test.echo", None).await;

        let snapshot = budget
            .snapshot(&zone)
            .await
            .expect("budget policy should produce a snapshot");
        assert_eq!(snapshot.budgets[0].used, 1);
        assert_eq!(snapshot.budgets[0].remaining, 9);
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn connector_process_runner_handles_multiple_roundtrips_with_test_connector() {
        let binary = compiled_test_connector_binary();
        let mut runner = ConnectorProcessRunner::spawn(
            &binary.display().to_string(),
            &[],
            &BTreeMap::from([(
                "FCP_TEST_CONNECTOR_ID".to_string(),
                "fcp.test.runner:utility:1.0.0".to_string(),
            )]),
        )
        .await
        .expect("spawn test connector");

        let configured = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            runner.request("configure", json!({})),
        )
        .await
        .expect("configure should not hang")
        .expect("configure should succeed");
        assert_eq!(configured["result"]["status"], "ok");

        let health_response = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            runner.request("health", json!({})),
        )
        .await
        .expect("health should not hang")
        .expect("health should succeed");
        assert_eq!(health_response["result"]["status"]["state"], "ready");
        assert!(health_response["result"]["status"]["error"].is_null());
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn connector_process_runner_rejects_mismatched_response_id_and_poisoned_transport() {
        let script = r#"while IFS= read -r _line; do printf '%s\n' '{"jsonrpc":"2.0","id":"stale","result":{"status":"wrong"}}'; done"#;
        let args = vec!["-c".to_string(), script.to_string()];
        let mut runner = ConnectorProcessRunner::spawn("sh", &args, &BTreeMap::new())
            .await
            .expect("spawn mismatched-id connector");

        let error = runner
            .request("health", json!({}))
            .await
            .expect_err("mismatched response id must be rejected");
        assert!(
            error
                .to_string()
                .contains("response id \"stale\" did not match request id"),
            "unexpected error: {error}"
        );

        let retry_error = runner
            .request("health", json!({}))
            .await
            .expect_err("desynchronized transport must stay poisoned");
        assert_eq!(retry_error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(
            retry_error
                .to_string()
                .contains("transport is desynchronized"),
            "unexpected retry error: {retry_error}"
        );
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn connector_process_runner_rejects_oversized_stdout_line_and_poisoned_transport() {
        let overlong_bytes = CONNECTOR_RPC_MAX_STDOUT_LINE_BYTES + 1;
        let script = format!(
            r#"while IFS= read -r _line; do
  i=0
  while [ "$i" -lt {overlong_bytes} ]; do
    printf x
    i=$((i + 1))
  done
  printf '\n'
done"#
        );
        let args = vec!["-c".to_string(), script];
        let mut runner = ConnectorProcessRunner::spawn("sh", &args, &BTreeMap::new())
            .await
            .expect("spawn overlong-line connector");

        let error = runner
            .request("health", json!({}))
            .await
            .expect_err("oversized stdout frame must be rejected");
        assert!(
            error
                .to_string()
                .contains("stdout frame exceeded 65536 bytes"),
            "unexpected error: {error}"
        );

        let retry_error = runner
            .request("health", json!({}))
            .await
            .expect_err("oversized stdout frame must poison transport");
        assert_eq!(retry_error.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn connector_process_runner_drop_reaps_long_running_process() {
        let pid = {
            let args = vec!["-c".to_string(), "while :; do sleep 1; done".to_string()];
            let runner = ConnectorProcessRunner::spawn("sh", &args, &BTreeMap::new())
                .await
                .expect("spawn long-running process");
            runner._child.id().expect("child pid should be available")
        };

        let mut reaped = false;
        for _ in 0..80 {
            let status = std::process::Command::new("sh")
                .args(["-c", &format!("kill -0 {pid} >/dev/null 2>&1")])
                .status()
                .expect("kill -0 should run");
            if !status.success() {
                reaped = true;
                break;
            }
            fcp_async_core::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        assert!(
            reaped,
            "child pid {pid} should be gone after drop-triggered cleanup"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_connector_supports_multiple_rpc_calls_after_configure() {
        let connector_id = "fcp.test.subprocess:utility:1.0.0";
        let connector = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            SubprocessConnector::spawn(
                subprocess_test_connector_config(connector_id),
                Arc::new(ResilienceLayer::default()),
                None,
            ),
        )
        .await
        .expect("spawn should not hang")
        .expect("spawn should succeed");

        let health = fcp_async_core::time::timeout(Duration::from_secs(2), connector.health())
            .await
            .expect("health should not hang")
            .expect("health should succeed");
        assert!(matches!(health.status, HealthState::Ready));

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

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_connector_queues_concurrent_health_requests() {
        let connector_id = "fcp.test.concurrent-health:utility:1.0.0";
        let connector = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            SubprocessConnector::spawn(
                subprocess_test_connector_config(connector_id),
                Arc::new(ResilienceLayer::default()),
                None,
            ),
        )
        .await
        .expect("spawn should not hang")
        .expect("spawn should succeed");

        let responses = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            join_all((0..8).map(|_| connector.health())),
        )
        .await
        .expect("concurrent health requests should not hang");

        assert_eq!(responses.len(), 8);
        for response in responses {
            let response = response.expect("health should succeed");
            assert!(matches!(response.status, HealthState::Ready));
        }
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_connector_queue_saturation_returns_error() {
        let connector_id = ConnectorId::from_static("fcp.test.queue-saturation:utility:1.0.0");
        let summary = ConnectorSummary {
            id: connector_id.clone(),
            name: connector_id.to_string(),
            description: None,
            version: semver::Version::new(1, 0, 0),
            categories: Vec::new(),
            tool_count: 0,
            max_safety_tier: SafetyTier::Safe,
            enabled: true,
            health: ConnectorHealth::healthy(),
            last_health_check: None,
        };
        let (runner_tx, runner_rx) = mpsc::channel::<ConnectorRpcRequest>(1);
        let (response_tx, _response_rx) = oneshot::channel();
        runner_tx
            .send(ConnectorRpcRequest {
                method: "health".to_string(),
                params: json!({}),
                response_tx,
            })
            .await
            .unwrap_or_else(|_| panic!("queue fill should succeed"));
        let runner_task = task::spawn(async move {
            let _runner_rx = runner_rx;
            fcp_async_core::time::sleep(CONNECTOR_RPC_IO_TIMEOUT + Duration::from_secs(1)).await;
        });
        let connector = SubprocessConnector {
            summary,
            runner_tx,
            _runner_task: runner_task,
            resilience: Arc::new(ResilienceLayer::default()),
            capability_verifying_key: None,
            handshaken_zone: Mutex::new(None),
        };
        connector.resilience.ensure_connector(&connector.summary.id);

        let error = fcp_async_core::time::timeout(
            CONNECTOR_RPC_IO_TIMEOUT + Duration::from_secs(2),
            connector.health(),
        )
        .await
        .expect("queue saturation should fail before outer timeout")
        .expect_err("queue saturation should return an error");

        assert!(
            error
                .to_string()
                .contains("connector dispatcher queue timed out"),
            "unexpected error: {error}"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_connector_dispatcher_allows_fast_response_before_slow_response() {
        let (runner_tx, mut runner_rx) = mpsc::channel::<ConnectorRpcRequest>(4);
        let (slow_seen_tx, slow_seen_rx) = oneshot::channel();
        let (release_slow_tx, release_slow_rx) = oneshot::channel::<()>();
        let runner_task = task::spawn(async move {
            let mut slow_seen_tx = Some(slow_seen_tx);
            let mut release_slow_rx = Some(release_slow_rx);
            while let Some(request) = runner_rx.recv().await {
                match request.method.as_str() {
                    "health" => {
                        if let Some(tx) = slow_seen_tx.take() {
                            let _ = tx.send(());
                        }
                        let release = release_slow_rx
                            .take()
                            .expect("test sends exactly one slow health request");
                        task::spawn_detached(async move {
                            let _ = release.await;
                            let _ = request.response_tx.send(Ok(json!({
                                "result": dispatcher_health_result(),
                            })));
                        });
                    }
                    "configure" => {
                        let _ = request.response_tx.send(Ok(json!({
                            "result": { "status": "ok" },
                        })));
                    }
                    method => {
                        let _ = request.response_tx.send(Ok(json!({
                            "error": { "message": format!("unexpected method {method}") },
                        })));
                    }
                }
            }
        });
        let connector = dispatcher_test_connector(
            "fcp.test.dispatch-fast-response:utility:1.0.0",
            runner_tx,
            runner_task,
        );

        let slow_health = {
            let connector = Arc::clone(&connector);
            task::spawn(async move { connector.health().await })
        };
        slow_seen_rx
            .await
            .expect("slow health request should reach dispatcher");

        fcp_async_core::time::timeout(
            Duration::from_secs(2),
            connector.configure(json!({ "mode": "fast" })),
        )
        .await
        .expect("fast configure should complete before slow health is released")
        .expect("fast configure should succeed");
        assert!(
            !slow_health.is_finished(),
            "slow health should still be waiting for its release signal"
        );

        let _ = release_slow_tx.send(());
        let health = slow_health
            .await
            .expect("slow health task should join")
            .expect("slow health should succeed after release");
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_connector_dropped_response_receiver_does_not_stop_dispatcher() {
        let (runner_tx, mut runner_rx) = mpsc::channel::<ConnectorRpcRequest>(4);
        let (first_seen_tx, first_seen_rx) = oneshot::channel();
        let (release_first_tx, release_first_rx) = oneshot::channel::<()>();
        let runner_task = task::spawn(async move {
            let mut first_seen_tx = Some(first_seen_tx);
            let mut release_first_rx = Some(release_first_rx);
            while let Some(request) = runner_rx.recv().await {
                if first_seen_tx.is_some() {
                    let tx = first_seen_tx
                        .take()
                        .expect("first-seen sender should exist");
                    let release = release_first_rx
                        .take()
                        .expect("first release receiver should exist");
                    task::spawn_detached(async move {
                        let _ = tx.send(());
                        let _ = release.await;
                        let _ = request.response_tx.send(Ok(json!({
                            "result": dispatcher_health_result(),
                        })));
                    });
                } else {
                    let _ = request.response_tx.send(Ok(json!({
                        "result": { "status": "ok" },
                    })));
                }
            }
        });
        let connector = dispatcher_test_connector(
            "fcp.test.dispatch-dropped-receiver:utility:1.0.0",
            runner_tx,
            runner_task,
        );

        let cancelled_health = {
            let connector = Arc::clone(&connector);
            task::spawn(async move { connector.health().await })
        };
        first_seen_rx
            .await
            .expect("first request should reach dispatcher");
        cancelled_health.abort();
        let join_error = cancelled_health
            .await
            .expect_err("aborted health task should report cancellation");
        assert!(join_error.is_cancelled());

        let _ = release_first_tx.send(());
        fcp_async_core::time::timeout(
            Duration::from_secs(2),
            connector.configure(json!({ "after": "cancelled-receiver" })),
        )
        .await
        .expect("dispatcher should continue after a failed oneshot send")
        .expect("later configure should succeed");
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_connector_closed_dispatcher_prevents_reuse_after_task_exit() {
        let (runner_tx, mut runner_rx) = mpsc::channel::<ConnectorRpcRequest>(4);
        let runner_task = task::spawn(async move {
            if let Some(request) = runner_rx.recv().await {
                drop(request);
            }
        });
        let connector = dispatcher_test_connector(
            "fcp.test.dispatcher-task-exit:utility:1.0.0",
            runner_tx,
            runner_task,
        );

        let first_error = fcp_async_core::time::timeout(Duration::from_secs(2), connector.health())
            .await
            .expect("closed dispatcher response should not hang")
            .expect_err("dropped dispatcher response should fail");
        assert!(
            first_error
                .to_string()
                .contains("connector dispatcher stopped before replying"),
            "unexpected first error: {first_error}"
        );

        let retry_error =
            fcp_async_core::time::timeout(Duration::from_secs(2), connector.configure(json!({})))
                .await
                .expect("closed dispatcher send should not hang")
                .expect_err("closed dispatcher should reject reuse");
        assert!(
            retry_error
                .to_string()
                .contains("connector dispatcher unavailable"),
            "unexpected retry error: {retry_error}"
        );
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn connector_process_runner_discards_late_timeout_reply_from_earlier_epoch() {
        let script = r#"first=1
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  if [ "$first" -eq 1 ]; then
    first=0
    sleep 0.2
    printf '{"jsonrpc":"2.0","id":"%s","result":{"status":"stale"}}\n' "$id"
  else
    printf '{"jsonrpc":"2.0","id":"%s","result":{"status":"fresh"}}\n' "$id"
  fi
done"#;
        let args = vec!["-c".to_string(), script.to_string()];
        let mut runner = ConnectorProcessRunner::spawn("sh", &args, &BTreeMap::new())
            .await
            .expect("spawn timeout connector");

        let timeout_error = runner
            .request_with_timeout("health", json!({}), Duration::from_millis(50))
            .await
            .expect_err("first request should time out");
        assert_eq!(timeout_error.kind(), std::io::ErrorKind::TimedOut);

        let response = runner
            .request_with_timeout("health", json!({}), Duration::from_secs(1))
            .await
            .expect("late stale reply should be discarded and second request should succeed");
        assert_eq!(response["result"]["status"], "fresh");
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_connector_invoke_performs_handshake_automatically() {
        let connector_id = "fcp.test.handshake:utility:1.0.0";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let connector = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            SubprocessConnector::spawn(
                subprocess_test_connector_config_requiring_handshake(connector_id),
                Arc::new(ResilienceLayer::default()),
                Some(signing_key.verifying_key().to_bytes()),
            ),
        )
        .await
        .expect("spawn should not hang")
        .expect("spawn should succeed");

        let response = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            connector.invoke(InvokeRequest {
                r#type: "invoke".to_string(),
                id: RequestId::random(),
                connector_id: connector_id.parse().expect("connector id"),
                operation: OperationId::from_static("test.echo"),
                zone_id: ZoneId::work(),
                input: json!({ "message": "hello from host test" }),
                capability_token: test_capability_token(
                    &signing_key,
                    "cap.test.echo",
                    "test.echo",
                    "z:work",
                ),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            }),
        )
        .await
        .expect("invoke should not hang")
        .expect("invoke should succeed");

        assert_eq!(response.status, InvokeStatus::Ok);
        assert_eq!(
            response.result.expect("result")["echo"]["message"],
            "hello from host test"
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_connector_simulate_performs_handshake_automatically() {
        let connector_id = "fcp.test.simulate-handshake:utility:1.0.0";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let connector = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            SubprocessConnector::spawn(
                subprocess_test_connector_config_requiring_handshake(connector_id),
                Arc::new(ResilienceLayer::default()),
                Some(signing_key.verifying_key().to_bytes()),
            ),
        )
        .await
        .expect("spawn should not hang")
        .expect("spawn should succeed");

        let response = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            connector.simulate(SimulateRequest {
                r#type: "simulate".to_string(),
                id: RequestId::random(),
                connector_id: connector_id.parse().expect("connector id"),
                operation: OperationId::from_static("test.echo"),
                zone_id: ZoneId::work(),
                input: json!({ "message": "hello from simulate host test" }),
                capability_token: test_capability_token(
                    &signing_key,
                    "cap.test.echo",
                    "test.echo",
                    "z:work",
                ),
                estimate_cost: false,
                check_availability: false,
                context: None,
                correlation_id: None,
            }),
        )
        .await
        .expect("simulate should not hang")
        .expect("simulate should succeed");

        assert!(response.would_succeed);
        assert!(response.failure_reason.is_none());
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_connector_concurrent_same_zone_invokes_all_succeed() {
        // br-j1pjg regression: two concurrent same-zone invokes on a
        // just-spawned connector must both complete successfully
        // without deadlocking. With the pre-fix pattern
        // (read-then-await-then-write on handshaken_zone) two callers
        // could both miss the cache and race; post-fix the mutex is
        // held across the handshake RPC so the second caller coalesces
        // onto the cached zone. We cannot assert RPC count=1 here
        // without a connector-side counter probe (filed as a follow-up
        // bead on fcp-test-connector) — this test at minimum pins the
        // no-deadlock + both-succeed invariant.
        let connector_id = "fcp.test.concurrent-handshake:utility:1.0.0";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let connector = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            SubprocessConnector::spawn(
                subprocess_test_connector_config_requiring_handshake(connector_id),
                Arc::new(ResilienceLayer::default()),
                Some(signing_key.verifying_key().to_bytes()),
            ),
        )
        .await
        .expect("spawn should not hang")
        .expect("spawn should succeed");

        let make_request = || InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({ "message": "concurrent probe" }),
            capability_token: test_capability_token(
                &signing_key,
                "cap.test.echo",
                "test.echo",
                "z:work",
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let responses = fcp_async_core::time::timeout(
            Duration::from_secs(5),
            join_all((0..8).map(|_| connector.invoke(make_request()))),
        )
        .await
        .expect("concurrent same-zone invokes should not hang");

        assert_eq!(responses.len(), 8);
        for response in responses {
            let response = response.expect("invoke should succeed");
            assert_eq!(response.status, InvokeStatus::Ok);
        }
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_connector_concurrent_cross_zone_invokes_do_not_invalidate_earlier_zone() {
        // br-zkl3b regression: the connector handshake is zone-bound, so
        // a later caller for a different zone must not be able to
        // re-handshake the subprocess and invalidate an earlier caller
        // before its invoke RPC is queued.
        let connector_id = "fcp.test.concurrent-cross-zone-handshake:utility:1.0.0";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let connector = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            SubprocessConnector::spawn(
                subprocess_test_connector_config_requiring_handshake(connector_id),
                Arc::new(ResilienceLayer::default()),
                Some(signing_key.verifying_key().to_bytes()),
            ),
        )
        .await
        .expect("spawn should not hang")
        .expect("spawn should succeed");

        let make_request = |zone_id: ZoneId, message: &'static str| InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: connector_id.parse().expect("connector id"),
            operation: OperationId::from_static("test.echo"),
            capability_token: test_capability_token(
                &signing_key,
                "cap.test.echo",
                "test.echo",
                zone_id.as_str(),
            ),
            zone_id,
            input: json!({ "message": message }),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let responses = fcp_async_core::time::timeout(
            Duration::from_secs(5),
            join_all((0..8).map(|idx| {
                let request = if idx % 2 == 0 {
                    make_request(ZoneId::work(), "work")
                } else {
                    make_request(ZoneId::private(), "private")
                };
                connector.invoke(request)
            })),
        )
        .await
        .expect("concurrent cross-zone invokes should not hang");

        assert_eq!(responses.len(), 8);
        for response in responses {
            let response = response.expect("invoke should succeed");
            assert_eq!(response.status, InvokeStatus::Ok);
        }
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_connector_invoke_fails_when_handshake_is_rejected() {
        let connector_id = "fcp.test.handshake-rejected:utility:1.0.0";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let connector = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            SubprocessConnector::spawn(
                subprocess_test_connector_config_with_handshake_mode(connector_id, "rejected"),
                Arc::new(ResilienceLayer::default()),
                Some(signing_key.verifying_key().to_bytes()),
            ),
        )
        .await
        .expect("spawn should not hang")
        .expect("spawn should succeed");

        let error = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            connector.invoke(InvokeRequest {
                r#type: "invoke".to_string(),
                id: RequestId::random(),
                connector_id: connector_id.parse().expect("connector id"),
                operation: OperationId::from_static("test.echo"),
                zone_id: ZoneId::work(),
                input: json!({ "message": "should fail at handshake" }),
                capability_token: test_capability_token(
                    &signing_key,
                    "cap.test.echo",
                    "test.echo",
                    "z:work",
                ),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            }),
        )
        .await
        .expect("invoke should not hang")
        .expect_err("invoke should fail");

        assert!(error.to_string().contains("handshake rejected"));
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_connector_invoke_fails_when_handshake_nonce_mismatches() {
        let connector_id = "fcp.test.handshake-bad-nonce:utility:1.0.0";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let connector = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            SubprocessConnector::spawn(
                subprocess_test_connector_config_with_handshake_mode(connector_id, "bad_nonce"),
                Arc::new(ResilienceLayer::default()),
                Some(signing_key.verifying_key().to_bytes()),
            ),
        )
        .await
        .expect("spawn should not hang")
        .expect("spawn should succeed");

        let error = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            connector.invoke(InvokeRequest {
                r#type: "invoke".to_string(),
                id: RequestId::random(),
                connector_id: connector_id.parse().expect("connector id"),
                operation: OperationId::from_static("test.echo"),
                zone_id: ZoneId::work(),
                input: json!({ "message": "should fail at handshake" }),
                capability_token: test_capability_token(
                    &signing_key,
                    "cap.test.echo",
                    "test.echo",
                    "z:work",
                ),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            }),
        )
        .await
        .expect("invoke should not hang")
        .expect_err("invoke should fail");

        assert!(error.to_string().contains("handshake nonce mismatch"));
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
                    None,
                ),
            )
            .await
            .expect("spawn should not hang")
            .expect("spawn should succeed");

            let health = fcp_async_core::time::timeout(Duration::from_secs(2), connector.health())
                .await
                .expect("health should not hang")
                .expect("health should succeed");
            assert!(matches!(health.status, HealthState::Ready));

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
            SubprocessRegistry::from_configs(
                vec![subprocess_test_connector_config(connector_id.as_str())],
                None,
            ),
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

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_registry_apply_configs_reconciles_live_inventory() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping live registry apply test");
            return;
        }
        let first_id = ConnectorId::from_static("fcp.test.registry-apply-one:utility:1.0.0");
        let second_id = ConnectorId::from_static("fcp.test.registry-apply-two:utility:1.0.0");
        let registry = SubprocessRegistry::from_configs(
            vec![subprocess_test_connector_config(first_id.as_str())],
            None,
        )
        .await
        .expect("registry construction should succeed");

        let add_report = registry
            .apply_configs(vec![
                subprocess_test_connector_config(first_id.as_str()),
                subprocess_test_connector_config(second_id.as_str()),
            ])
            .await
            .expect("registry apply should succeed");
        assert!(add_report.added.iter().any(|id| id == second_id.as_str()));
        assert_eq!(registry.list().await.len(), 2);

        let remove_report = registry
            .apply_configs(vec![subprocess_test_connector_config(second_id.as_str())])
            .await
            .expect("registry removal should succeed");
        assert!(
            remove_report
                .removed
                .iter()
                .any(|id| id == first_id.as_str())
        );
        let remaining = registry.list().await;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, second_id);
    }

    #[test]
    fn parse_cli_action_accepts_help() {
        let action =
            parse_cli_action_from_args(["fcp-host", "--help"]).expect("help flag should parse");
        assert_eq!(action, CliAction::PrintHelp);
    }

    #[test]
    fn parse_cli_action_accepts_version() {
        let action = parse_cli_action_from_args(["fcp-host", "--version"])
            .expect("version flag should parse");
        assert_eq!(action, CliAction::PrintVersion);
    }

    #[test]
    fn parse_cli_action_rejects_unexpected_arguments() {
        let err = parse_cli_action_from_args(["fcp-host", "--bind", "0.0.0.0:9090"])
            .expect_err("unsupported CLI args should fail closed");
        assert!(matches!(err, HostError::InvalidFilter(_)));
        assert!(err.to_string().contains("unexpected CLI arguments"));
    }

    #[test]
    fn read_optional_env_string_rejects_non_unicode_values() {
        let err = read_optional_env_string_from_result(
            "FCP_HOST_BIND",
            Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
                "bad-value",
            ))),
        )
        .expect_err("non-unicode env should fail");
        assert!(matches!(err, HostError::InvalidFilter(_)));
        assert!(
            err.to_string()
                .contains("FCP_HOST_BIND contains non-unicode data")
        );
    }

    #[test]
    fn read_optional_trimmed_env_string_treats_blank_as_unset() {
        let value = read_optional_trimmed_env_string_from_result(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            Ok("   ".to_string()),
        )
        .expect("blank env should decode");
        assert_eq!(value, None);
    }

    #[test]
    fn parse_zone_policies_json_accepts_zone_keyed_map() {
        let policy = host_runtime_policy(ZoneId::work());
        let raw = serde_json::to_string(&HashMap::from([(
            ZoneId::work().as_str().to_string(),
            policy,
        )]))
        .expect("serialize zone policy map");

        let parsed = parse_zone_policies_json(&raw).expect("zone policy map should parse");

        assert!(parsed.contains_key(&ZoneId::work()));
    }

    #[test]
    fn parse_zone_policies_json_rejects_mismatched_policy_zone() {
        let policy = host_runtime_policy(ZoneId::private());
        let raw = serde_json::to_string(&HashMap::from([(
            ZoneId::work().as_str().to_string(),
            policy,
        )]))
        .expect("serialize zone policy map");

        let err = parse_zone_policies_json(&raw).expect_err("zone mismatch must fail closed");

        assert!(matches!(err, HostError::InvalidFilter(_)));
        assert!(err.to_string().contains("does not match policy zone_id"));
    }

    #[test]
    fn resolve_verifying_key_falls_back_to_file_when_inline_value_is_blank() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("capability.pub");
        let signing_key =
            fcp_crypto::ed25519::Ed25519SigningKey::from_bytes(&[7_u8; 32]).expect("test key");
        let expected = signing_key.verifying_key().to_bytes();
        std::fs::write(&file, hex::encode(expected)).expect("write verifying key file");

        let inline = read_optional_trimmed_env_string_from_result(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            Ok("   ".to_string()),
        )
        .expect("blank inline env should decode");
        let file_value = read_optional_trimmed_env_string_from_result(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY_FILE",
            Ok(format!("  {}  ", file.display())),
        )
        .expect("file env should decode");

        let resolved = resolve_verifying_key_from_sources(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            inline,
            "FCP_HOST_CAPABILITY_PUBLIC_KEY_FILE",
            file_value,
        )
        .expect("file fallback should parse")
        .expect("verifying key should load");
        assert_eq!(resolved.to_bytes(), expected);
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
    fn validate_admin_authorization_rejects_missing_header() {
        let state = AppState {
            registry: Arc::new(empty_registry(1)),
            doctor: DoctorService::new(Arc::new(empty_registry(1))),
            budget: Arc::new(BudgetPolicyEngine::new()),
            discovery: Arc::new(DiscoveryEndpoint::new(
                Arc::new(empty_registry(1)),
                Arc::new(BudgetPolicyEngine::new()),
            )),
            cancellation: Arc::new(CancellationController::new()),
            lifecycle: Arc::new(HostAdminStateStore::new()),
            rollout: Arc::new(RolloutController::new(
                Arc::new(empty_registry(1)),
                Arc::new(HostAdminStateStore::new()),
            )),
            supply_chain: Arc::new(SupplyChainGate::default()),
            capability_verifying_key: None,
            revocation_cascade: Arc::new(RevocationCascadeVerifier::default()),
            hybrid_owner_verifier: None,
            approval_verifying_key: None,
            admin_bearer_token: Some(Arc::<str>::from("topsecret".to_string())),
            connectors_file: None,
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
            started_at: Instant::now(),
        };

        let error =
            validate_admin_authorization(&state, &HeaderMap::new()).expect_err("missing auth");
        assert!(error.to_string().contains("Authorization"));
    }

    #[test]
    fn validate_admin_authorization_accepts_matching_bearer_token() {
        let registry = Arc::new(empty_registry(1));
        let budget = Arc::new(BudgetPolicyEngine::new());
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let state = AppState {
            registry: Arc::clone(&registry),
            doctor: DoctorService::new(Arc::clone(&registry)),
            budget: Arc::clone(&budget),
            discovery: Arc::new(DiscoveryEndpoint::new(
                Arc::clone(&registry),
                Arc::clone(&budget),
            )),
            cancellation: Arc::new(CancellationController::new()),
            lifecycle: Arc::clone(&lifecycle),
            rollout: Arc::new(RolloutController::new(
                Arc::clone(&registry),
                Arc::clone(&lifecycle),
            )),
            supply_chain: Arc::new(SupplyChainGate::default()),
            capability_verifying_key: None,
            revocation_cascade: Arc::new(RevocationCascadeVerifier::default()),
            hybrid_owner_verifier: None,
            approval_verifying_key: None,
            admin_bearer_token: Some(Arc::<str>::from("topsecret".to_string())),
            connectors_file: None,
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
            started_at: Instant::now(),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer topsecret"),
        );
        headers.insert(ADMIN_ZONE_HEADER, HeaderValue::from_static("z:owner"));

        validate_admin_authorization(&state, &headers).expect("matching token");
    }

    #[test]
    fn validate_admin_authorization_accepts_lowercase_bearer_scheme() {
        let registry = Arc::new(empty_registry(1));
        let budget = Arc::new(BudgetPolicyEngine::new());
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let state = AppState {
            registry: Arc::clone(&registry),
            doctor: DoctorService::new(Arc::clone(&registry)),
            budget: Arc::clone(&budget),
            discovery: Arc::new(DiscoveryEndpoint::new(
                Arc::clone(&registry),
                Arc::clone(&budget),
            )),
            cancellation: Arc::new(CancellationController::new()),
            lifecycle: Arc::clone(&lifecycle),
            rollout: Arc::new(RolloutController::new(
                Arc::clone(&registry),
                Arc::clone(&lifecycle),
            )),
            supply_chain: Arc::new(SupplyChainGate::default()),
            capability_verifying_key: None,
            revocation_cascade: Arc::new(RevocationCascadeVerifier::default()),
            hybrid_owner_verifier: None,
            approval_verifying_key: None,
            admin_bearer_token: Some(Arc::<str>::from("topsecret".to_string())),
            connectors_file: None,
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
            started_at: Instant::now(),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("bearer topsecret"),
        );
        headers.insert(ADMIN_ZONE_HEADER, HeaderValue::from_static("z:owner"));

        validate_admin_authorization(&state, &headers).expect("matching token");
    }

    #[test]
    fn validate_admin_authorization_rejects_mismatched_bearer_token() {
        let registry = Arc::new(empty_registry(1));
        let budget = Arc::new(BudgetPolicyEngine::new());
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let state = AppState {
            registry: Arc::clone(&registry),
            doctor: DoctorService::new(Arc::clone(&registry)),
            budget: Arc::clone(&budget),
            discovery: Arc::new(DiscoveryEndpoint::new(
                Arc::clone(&registry),
                Arc::clone(&budget),
            )),
            cancellation: Arc::new(CancellationController::new()),
            lifecycle: Arc::clone(&lifecycle),
            rollout: Arc::new(RolloutController::new(
                Arc::clone(&registry),
                Arc::clone(&lifecycle),
            )),
            supply_chain: Arc::new(SupplyChainGate::default()),
            capability_verifying_key: None,
            revocation_cascade: Arc::new(RevocationCascadeVerifier::default()),
            hybrid_owner_verifier: None,
            approval_verifying_key: None,
            admin_bearer_token: Some(Arc::<str>::from("topsecret".to_string())),
            connectors_file: None,
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
            started_at: Instant::now(),
        };

        // Same length as the real token — exercises the constant-time
        // branch rather than an early length-mismatch return.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer topsecrex"),
        );
        headers.insert(ADMIN_ZONE_HEADER, HeaderValue::from_static("z:owner"));

        let error = validate_admin_authorization(&state, &headers)
            .expect_err("mismatched token must be rejected");
        assert!(
            error.to_string().contains("rejected"),
            "unexpected error: {error}"
        );

        // Differing-length token — also rejected.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong"),
        );
        headers.insert(ADMIN_ZONE_HEADER, HeaderValue::from_static("z:owner"));
        validate_admin_authorization(&state, &headers)
            .expect_err("short mismatched token must be rejected");
    }

    #[test]
    fn validate_admin_authorization_rejects_missing_owner_zone_header() {
        let registry = Arc::new(empty_registry(1));
        let budget = Arc::new(BudgetPolicyEngine::new());
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let state = AppState {
            registry: Arc::clone(&registry),
            doctor: DoctorService::new(Arc::clone(&registry)),
            budget: Arc::clone(&budget),
            discovery: Arc::new(DiscoveryEndpoint::new(
                Arc::clone(&registry),
                Arc::clone(&budget),
            )),
            cancellation: Arc::new(CancellationController::new()),
            lifecycle: Arc::clone(&lifecycle),
            rollout: Arc::new(RolloutController::new(
                Arc::clone(&registry),
                Arc::clone(&lifecycle),
            )),
            supply_chain: Arc::new(SupplyChainGate::default()),
            capability_verifying_key: None,
            revocation_cascade: Arc::new(RevocationCascadeVerifier::default()),
            hybrid_owner_verifier: None,
            approval_verifying_key: None,
            admin_bearer_token: Some(Arc::<str>::from("topsecret".to_string())),
            connectors_file: None,
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
            started_at: Instant::now(),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer topsecret"),
        );

        let error = validate_admin_authorization(&state, &headers)
            .expect_err("admin API must require owner-zone assertion");
        assert!(
            error.to_string().contains(ADMIN_ZONE_HEADER),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validate_admin_authorization_rejects_non_owner_zone_header() {
        let registry = Arc::new(empty_registry(1));
        let budget = Arc::new(BudgetPolicyEngine::new());
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let state = AppState {
            registry: Arc::clone(&registry),
            doctor: DoctorService::new(Arc::clone(&registry)),
            budget: Arc::clone(&budget),
            discovery: Arc::new(DiscoveryEndpoint::new(
                Arc::clone(&registry),
                Arc::clone(&budget),
            )),
            cancellation: Arc::new(CancellationController::new()),
            lifecycle: Arc::clone(&lifecycle),
            rollout: Arc::new(RolloutController::new(
                Arc::clone(&registry),
                Arc::clone(&lifecycle),
            )),
            supply_chain: Arc::new(SupplyChainGate::default()),
            capability_verifying_key: None,
            revocation_cascade: Arc::new(RevocationCascadeVerifier::default()),
            hybrid_owner_verifier: None,
            approval_verifying_key: None,
            admin_bearer_token: Some(Arc::<str>::from("topsecret".to_string())),
            connectors_file: None,
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
            started_at: Instant::now(),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer topsecret"),
        );
        headers.insert(ADMIN_ZONE_HEADER, HeaderValue::from_static("z:work"));

        let error = validate_admin_authorization(&state, &headers)
            .expect_err("admin API must reject non-owner zone assertions");
        assert!(
            error.to_string().contains("z:owner"),
            "unexpected error: {error}"
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

    fn empty_registry(version: u64) -> SubprocessRegistry {
        SubprocessRegistry {
            state: Arc::new(RwLock::new(RegistryState::default())),
            resilience: Arc::new(ResilienceLayer::default()),
            version: Arc::new(AtomicU64::new(version)),
            capability_verifying_key: None,
            rate_limiters: Arc::new(HostRateLimiterStore::default()),
        }
    }

    #[test]
    fn subprocess_registry_version() {
        let registry = empty_registry(42);
        assert_eq!(registry.version(), 42);
    }

    #[test]
    fn subprocess_registry_clone() {
        let registry = empty_registry(7);
        let cloned = registry.clone();
        assert_eq!(cloned.version(), 7);
        let inventory =
            fcp_async_core::runtime::block_on_sync(cloned.inventory()).expect("inventory query");
        assert!(inventory.is_empty());
    }

    // ── AppState clone ──

    #[fcp_async_core::runtime::test]
    async fn app_state_clone_preserves_started_at() {
        let registry = Arc::new(empty_registry(1));
        let doctor = DoctorService::new(Arc::clone(&registry));
        let budget = Arc::new(BudgetPolicyEngine::new());
        let discovery = Arc::new(DiscoveryEndpoint::new(
            Arc::clone(&registry),
            Arc::clone(&budget),
        ));
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let rollout = Arc::new(RolloutController::new(
            Arc::clone(&registry),
            Arc::clone(&lifecycle),
        ));
        let state = AppState {
            registry,
            doctor,
            budget,
            discovery,
            cancellation: Arc::new(CancellationController::new()),
            lifecycle,
            rollout,
            supply_chain: Arc::new(SupplyChainGate::default()),
            capability_verifying_key: None,
            revocation_cascade: Arc::new(RevocationCascadeVerifier::default()),
            hybrid_owner_verifier: None,
            approval_verifying_key: None,
            admin_bearer_token: None,
            connectors_file: None,
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
            started_at: Instant::now(),
        };
        let cloned = state.clone();
        // started_at should be equal (same instant)
        assert_eq!(state.started_at, cloned.started_at);
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn rollout_evaluate_handler_uses_lifecycle_pin_state_over_request_flag() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping rollout pin-state test");
            return;
        }

        let connector_id = ConnectorId::from_static("fcp.test.rollout-pinned:utility:1.0.0");
        let registry = Arc::new(
            SubprocessRegistry::from_configs(
                vec![subprocess_test_connector_config(connector_id.as_str())],
                None,
            )
            .await
            .expect("registry should load"),
        );
        let doctor = DoctorService::new(Arc::clone(&registry));
        let budget = Arc::new(BudgetPolicyEngine::new());
        let discovery = Arc::new(DiscoveryEndpoint::new(
            Arc::clone(&registry),
            Arc::clone(&budget),
        ));
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let rollout = Arc::new(RolloutController::new(
            Arc::clone(&registry),
            Arc::clone(&lifecycle),
        ));
        let state = Arc::new(AppState {
            registry,
            doctor,
            budget,
            discovery,
            cancellation: Arc::new(CancellationController::new()),
            lifecycle: Arc::clone(&lifecycle),
            rollout: Arc::clone(&rollout),
            supply_chain: Arc::new(SupplyChainGate::default()),
            capability_verifying_key: None,
            revocation_cascade: Arc::new(RevocationCascadeVerifier::default()),
            hybrid_owner_verifier: None,
            approval_verifying_key: None,
            admin_bearer_token: None,
            connectors_file: None,
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
            started_at: Instant::now(),
        });
        let version = semver::Version::new(1, 2, 0);
        let previous_version = semver::Version::new(1, 1, 0);
        let scheduled_at = Utc
            .with_ymd_and_hms(2026, 3, 24, 12, 0, 0)
            .single()
            .expect("valid schedule timestamp");
        let policy = rollout_handler_test_policy();
        rollout
            .schedule_canary(
                &connector_id,
                version.clone(),
                Some(previous_version),
                &policy,
                scheduled_at,
            )
            .await
            .expect("canary should schedule");
        lifecycle
            .pin(&connector_id, version)
            .await
            .expect("pin should persist");

        let Json(outcome) = rollout_evaluate_handler(
            State(state),
            Json(RolloutEvaluateRequest {
                connector_id: connector_id.to_string(),
                invocation_succeeded: true,
                latency_ms: Some(15),
                uptime_secs: 900,
                pinned: false,
                crashed: false,
                policy,
                observed_at: Some(scheduled_at + chrono::Duration::seconds(180)),
            }),
        )
        .await
        .expect("handler should succeed");

        assert_eq!(outcome.decision, RolloutDecision::Hold);
        assert_eq!(outcome.audit_event.reason_code, "pinned");
        assert!(outcome.evidence.pinned);
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
    fn configured_subprocess_archetype_defaults_to_unknown_when_unset() {
        let config = subprocess_test_connector_config("fcp.test.truth.archetype:utility:1.0.0");
        assert_eq!(
            configured_subprocess_archetype(&config),
            ConnectorArchetype::Unknown
        );
    }

    #[test]
    fn configured_subprocess_archetype_preserves_explicit_request_response() {
        let mut config =
            subprocess_test_connector_config("fcp.test.truth.explicit-archetype:utility:1.0.0");
        config.env.insert(
            "FCP_TEST_CONNECTOR_ARCHETYPE".to_string(),
            "request_response".to_string(),
        );
        assert_eq!(
            configured_subprocess_archetype(&config),
            ConnectorArchetype::RequestResponse
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn subprocess_registry_rate_limits_remain_unknown_without_declarations() {
        let connector_id = ConnectorId::from_static("fcp.test.truth.rate-limits:utility:1.0.0");
        let registry = SubprocessRegistry::from_configs(
            vec![subprocess_test_connector_config(connector_id.as_str())],
            None,
        )
        .await
        .expect("registry should load");

        assert_eq!(registry.get_rate_limits(&connector_id).await, None);
    }

    #[test]
    fn connector_config_debug() {
        let config = ConnectorConfig {
            id: "fcp.test:echo:1.0.0".to_string(),
            binary: "/bin/echo".to_string(),
            name: None,
            description: None,
            args: vec![],
            env: BTreeMap::new(),
            config: None,
            categories: vec![],
            version: None,
            allowed_zones: Vec::new(),
            allowed_operations: Vec::new(),
            enforce_empty_allow_lists: false,
        };
        let dbg = format!("{config:?}");
        assert!(dbg.contains("ConnectorConfig"));
        assert!(dbg.contains("fcp.test:echo:1.0.0"));
    }

    #[test]
    fn normalize_connector_config_payload_omits_empty_objects() {
        assert_eq!(normalize_connector_config_payload(json!({})), None);
        assert_eq!(
            normalize_connector_config_payload(json!({"profile": "work"})),
            Some(json!({"profile": "work"}))
        );
    }

    #[test]
    fn current_config_snapshot_source_prefers_active_revision_when_digest_matches() {
        let revision = ConfigRevisionRecord {
            revision_id: 7,
            previous_revision_id: Some(6),
            created_at: Utc::now(),
            created_by: Some("operator".to_string()),
            change_reason: Some("update".to_string()),
            payload: json!({"profile": "work"}),
            payload_digest: SanitizedConnectorConfig::from_payload(json!({"profile": "work"}))
                .expect("sanitized digest")
                .payload_digest,
            redacted_fields: Vec::new(),
            credential_references: Vec::new(),
            contains_inline_secrets: false,
        };
        let context = ConnectorConfigContext {
            raw_payload: json!({"profile": "work"}),
            current: SanitizedConnectorConfig::from_payload(json!({"profile": "work"}))
                .expect("sanitized current"),
            connector_state: Some(ConnectorAdminState {
                config_revisions: vec![revision.clone()],
                active_config_revision_id: Some(revision.revision_id),
                ..ConnectorAdminState::default()
            }),
        };

        assert_eq!(
            current_config_snapshot_source(&context),
            ConnectorConfigSnapshotSource::ActiveRevision
        );
    }

    #[test]
    fn ensure_expected_config_revision_rejects_mismatch() {
        let connector_id = ConnectorId::from_static("fcp.test:config-check:utility:1.0.0");
        let err = ensure_expected_config_revision(&connector_id, Some(11), Some(12))
            .expect_err("mismatch should be rejected");
        assert!(
            err.to_string()
                .contains("is at config revision 12, expected 11")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn host_lifecycle_manager_persists_records_and_pins_across_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("state").join("lifecycle.json");
        let connector_id = ConnectorId::from_static("fcp.test.lifecycle:utility:1.0.0");
        let previous_version = semver::Version::new(1, 4, 0);
        let current_version = semver::Version::new(1, 5, 0);

        let manager =
            HostAdminStateStore::with_state_path(state_path.clone()).expect("manager should load");
        let mut record = LifecycleRecord::new(connector_id.clone(), current_version.clone())
            .with_previous_version(previous_version.clone());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .expect("pending -> installing");
        record
            .transition(
                LifecycleState::Canary,
                TransitionReason::NewVersion {
                    from_version: previous_version.to_string(),
                    to_version: current_version.to_string(),
                },
            )
            .expect("installing -> canary");
        manager.save(&record).await.expect("save should persist");
        manager
            .pin(&connector_id, current_version.clone())
            .await
            .expect("pin should persist");

        let reloaded =
            HostAdminStateStore::with_state_path(state_path).expect("manager should reload");
        let restored_record = reloaded
            .get(&connector_id)
            .await
            .expect("get should succeed")
            .expect("record should exist");
        assert_eq!(
            serde_json::to_value(&restored_record).expect("record should serialize"),
            serde_json::to_value(&record).expect("record should serialize")
        );
        assert_eq!(
            reloaded.pinned_version(&connector_id).await,
            Some(current_version)
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn connector_inventory_apply_rolls_back_when_reconciliation_fails() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping inventory rollback test");
            return;
        }

        let work_dir = tempfile::tempdir().expect("tempdir");
        let lifecycle_dir = tempfile::tempdir().expect("tempdir");
        let connectors_file = work_dir.path().join("connectors.json");
        let connector_id = "fcp.test.rollback.inventory:utility:1.0.0";
        let original = subprocess_test_connector_config(connector_id);
        let lifecycle = Arc::new(
            HostAdminStateStore::with_state_path(failing_admin_state_path(&lifecycle_dir))
                .expect("lifecycle store should load"),
        );
        let state = test_app_state_with_connectors_file(
            vec![original.clone()],
            connectors_file.clone(),
            lifecycle,
        )
        .await;

        let mut updated = original.clone();
        updated.name = Some("Updated Name".to_string());
        updated.categories.push("rollback-check".to_string());

        let err = connector_inventory_apply_handler(
            State(Arc::clone(&state)),
            Json(ConnectorInventoryMutationRequest {
                kind: ConnectorInventoryMutationKind::Update,
                dry_run: false,
                connector: updated,
            }),
        )
        .await
        .expect_err("reconciliation failure should surface");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(err.1.contains("failed to reconcile admin state"));

        let persisted = read_connector_configs_file(&connectors_file)
            .expect("connectors file should remain readable");
        assert_eq!(persisted, vec![original.clone()]);

        let inventory = state.registry.inventory().await;
        assert_eq!(inventory, vec![original]);
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn connector_config_apply_rolls_back_when_reconciliation_fails() {
        if maybe_compiled_test_connector_binary().is_none() {
            eprintln!("compiled fcp-test-connector missing; skipping config rollback test");
            return;
        }

        let work_dir = tempfile::tempdir().expect("tempdir");
        let lifecycle_dir = tempfile::tempdir().expect("tempdir");
        let connectors_file = work_dir.path().join("connectors.json");
        let connector_id = ConnectorId::from_static("fcp.test.rollback.config:utility:1.0.0");
        let mut original = subprocess_test_connector_config(connector_id.as_str());
        original.config = Some(json!({ "profile": "v1" }));
        let lifecycle = Arc::new(
            HostAdminStateStore::with_state_path(failing_admin_state_path(&lifecycle_dir))
                .expect("lifecycle store should load"),
        );
        let state = test_app_state_with_connectors_file(
            vec![original.clone()],
            connectors_file.clone(),
            lifecycle,
        )
        .await;

        let err = apply_connector_config_payload(
            state.as_ref(),
            &connector_id,
            json!({ "profile": "v2" }),
            None,
            Some("test-suite".to_string()),
            Some("upgrade".to_string()),
        )
        .await
        .expect_err("reconciliation failure should roll back config");
        assert!(err.to_string().contains("failed to reconcile admin state"));

        let persisted = read_connector_configs_file(&connectors_file)
            .expect("connectors file should remain readable");
        assert_eq!(persisted, vec![original.clone()]);

        let inventory = state.registry.inventory().await;
        assert_eq!(inventory, vec![original]);
    }

    // ---- br-flywheel_connectors-t623k: X-Principal header ----

    #[test]
    fn extract_principal_header_absent_returns_none() {
        let headers = HeaderMap::new();
        assert_eq!(extract_principal_header(&headers), None);
    }

    #[test]
    fn extract_principal_header_reads_value() {
        let mut headers = HeaderMap::new();
        headers.insert(PRINCIPAL_HEADER, HeaderValue::from_static("user:alice"));
        assert_eq!(
            extract_principal_header(&headers),
            Some("user:alice".to_owned())
        );
    }

    #[test]
    fn extract_principal_header_trims_surrounding_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert(PRINCIPAL_HEADER, HeaderValue::from_static("  user:bob  "));
        assert_eq!(
            extract_principal_header(&headers),
            Some("user:bob".to_owned())
        );
    }

    #[test]
    fn extract_principal_header_empty_after_trim_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert(PRINCIPAL_HEADER, HeaderValue::from_static("   "));
        assert_eq!(extract_principal_header(&headers), None);
    }

    #[test]
    fn extract_principal_header_rejects_non_utf8_as_none() {
        // HeaderValue::from_bytes accepts non-ASCII; the `.to_str()` path
        // in extract_principal_header rejects it, falling back to None
        // rather than forwarding a lossy value as an asserted principal.
        let mut headers = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff, 0xfe, 0xfd])
            .expect("HeaderValue accepts arbitrary bytes");
        headers.insert(PRINCIPAL_HEADER, bad);
        assert_eq!(extract_principal_header(&headers), None);
    }

    // ── br-71lku: /rpc/cancel auth-bypass regression ──────────────

    fn cancel_route_test_state() -> Arc<AppState> {
        let registry = Arc::new(empty_registry(1));
        let budget = Arc::new(BudgetPolicyEngine::new());
        let lifecycle = Arc::new(HostAdminStateStore::new());
        Arc::new(AppState {
            registry: Arc::clone(&registry),
            doctor: DoctorService::new(Arc::clone(&registry)),
            budget: Arc::clone(&budget),
            discovery: Arc::new(DiscoveryEndpoint::new(
                Arc::clone(&registry),
                Arc::clone(&budget),
            )),
            cancellation: Arc::new(CancellationController::new()),
            lifecycle: Arc::clone(&lifecycle),
            rollout: Arc::new(RolloutController::new(
                Arc::clone(&registry),
                Arc::clone(&lifecycle),
            )),
            supply_chain: Arc::new(SupplyChainGate::default()),
            capability_verifying_key: None,
            revocation_cascade: Arc::new(RevocationCascadeVerifier::default()),
            hybrid_owner_verifier: None,
            approval_verifying_key: None,
            admin_bearer_token: Some(Arc::<str>::from("topsecret".to_string())),
            connectors_file: None,
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            invoke_audit: Arc::new(fcp_host::InvokeAuditChain::new()),
            started_at: Instant::now(),
        })
    }

    async fn issue_host_capability_test_token(
        lifecycle: &HostAdminStateStore,
        connector_id: &str,
        capability_id: &str,
        principal_id: &str,
        operations: Vec<String>,
    ) -> fcp_core::CapabilityToken {
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let issued = lifecycle
            .issue_capability_token(
                &fcp_host::CapabilityIssuanceRequest {
                    connector_id: connector_id.to_string(),
                    capability_id: capability_id.to_string(),
                    zone_id: ZoneId::work().to_string(),
                    principal_id: principal_id.to_string(),
                    operations,
                    ttl_secs: 3600,
                    not_before_delay_secs: None,
                    holder_node: None,
                    max_delegation_depth: 0,
                    resource_allow: Vec::new(),
                    resource_deny: Vec::new(),
                    max_calls: None,
                    max_bytes: None,
                    credential_allow: Vec::new(),
                    dry_run: false,
                },
                &signing_key,
            )
            .await
            .expect("issue cancel-self capability token");
        let token_b64 = issued
            .token_cbor_b64
            .expect("non-dry-run issuance should return a token");
        let token_bytes = base64::engine::general_purpose::STANDARD
            .decode(token_b64)
            .unwrap();
        fcp_core::CapabilityToken::from_raw(
            fcp_crypto::cose::CoseToken::from_cbor(&token_bytes)
                .expect("issued host capability token should decode"),
        )
    }

    async fn issue_cancel_self_test_token(
        lifecycle: &HostAdminStateStore,
        principal_id: &str,
    ) -> fcp_core::CapabilityToken {
        issue_host_capability_test_token(
            lifecycle,
            CANCEL_SELF_CONNECTOR_ID,
            CANCEL_SELF_CAPABILITY_ID,
            principal_id,
            vec![CANCEL_SELF_OPERATION_ID.to_string()],
        )
        .await
    }

    /// Construct a minimal app router that mirrors the production
    /// cancel mounts: admin cancel routes live in `protected_routes`
    /// behind `admin_auth_middleware`, while `/rpc/cancel-self`
    /// remains public and authenticates via capability token. This
    /// is the exact wiring pattern from the production `main()`
    /// builder, scoped down to the cancellation routes for the
    /// regression tests.
    fn cancel_test_app(state: Arc<AppState>) -> axum::Router {
        let protected = axum::Router::new()
            .route("/rpc/cancel", post(cancel_handler))
            .route("/rpc/operations/cancel", post(cancel_handler))
            .route_layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                admin_auth_middleware,
            ));
        axum::Router::new()
            .route("/rpc/cancel-self", post(cancel_self_handler))
            .merge(protected)
            .with_state(Arc::clone(&state))
    }

    async fn send_cancel_request(
        app: axum::Router,
        path: &str,
        body: serde_json::Value,
        extra_headers: &[(&str, &str)],
    ) -> axum::response::Response {
        use axum::body::Body;
        use axum::http::{Request, header::CONTENT_TYPE};
        use tower::util::ServiceExt;

        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header(CONTENT_TYPE, "application/json");
        for (k, v) in extra_headers {
            builder = builder.header(*k, *v);
        }
        let req = builder
            .body(Body::from(body.to_string()))
            .expect("build cancel request");

        app.oneshot(req).await.expect("router response")
    }

    async fn post_cancel_with_headers(
        app: axum::Router,
        path: &str,
        extra_headers: &[(&str, &str)],
    ) -> axum::http::StatusCode {
        send_cancel_request(
            app,
            path,
            serde_json::json!({
                "operation_id": "op-71lku-test",
                "reason": "user_requested",
            }),
            extra_headers,
        )
        .await
        .status()
    }

    #[fcp_async_core::runtime::test]
    async fn rpc_cancel_rejects_unauthenticated_request() {
        // br-71lku: a public caller with no Authorization header must
        // not be able to cancel another principal's operation by
        // setting a spoofable `X-Principal` header. The route is now
        // gated by admin_auth_middleware so the request is rejected
        // before it reaches cancel_handler / CancellationController.
        let state = cancel_route_test_state();
        let app = cancel_test_app(state);

        // No Authorization header, no admin zone header, but a
        // spoofed X-Principal — exactly the bypass shape from the
        // bead repro. Even a matching X-Principal value must be
        // rejected at the routing layer.
        let status =
            post_cancel_with_headers(app, "/rpc/cancel", &[("X-Principal", "user:test")]).await;
        assert_eq!(
            status,
            axum::http::StatusCode::FORBIDDEN,
            "unauthenticated cancel must be rejected at the routing layer"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn rpc_operations_cancel_rejects_unauthenticated_request() {
        // Same regression for the alias path /rpc/operations/cancel.
        let state = cancel_route_test_state();
        let app = cancel_test_app(state);
        let status = post_cancel_with_headers(
            app,
            "/rpc/operations/cancel",
            &[("X-Principal", "user:test")],
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    }

    #[fcp_async_core::runtime::test]
    async fn rpc_cancel_rejects_wrong_admin_bearer_token() {
        // Even with an Authorization header, a wrong bearer must be
        // rejected — locks in that the gate is the actual bearer
        // check, not just header presence.
        let state = cancel_route_test_state();
        let app = cancel_test_app(state);
        let status = post_cancel_with_headers(
            app,
            "/rpc/cancel",
            &[
                ("Authorization", "Bearer wrong-token"),
                (ADMIN_ZONE_HEADER, "z:owner"),
            ],
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    }

    #[fcp_async_core::runtime::test]
    async fn rpc_cancel_self_allows_verified_owner_without_admin_auth() {
        let state = cancel_route_test_state();
        state
            .cancellation
            .track_with_owner("op-self-owner", Some("user:test"));
        let token = issue_cancel_self_test_token(state.lifecycle.as_ref(), "user:test").await;
        let app = cancel_test_app(Arc::clone(&state));
        let response = send_cancel_request(
            app,
            "/rpc/cancel-self",
            serde_json::to_value(CancellationRequest {
                operation_id: "op-self-owner".to_string(),
                reason: CancelReason::UserRequested,
                cleanup: CleanupBehavior::BestEffort,
                return_partial: false,
                capability_token: Some(token),
            })
            .expect("serialize cancel-self request"),
            &[],
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read cancel-self body");
        let parsed: CancellationResponse =
            serde_json::from_slice(&body).expect("parse cancel-self response");
        assert_eq!(parsed.operation_id, "op-self-owner");
        assert_eq!(parsed.outcome, fcp_host::CancellationOutcome::Cancelled);
        assert!(state.cancellation.is_cancel_requested("op-self-owner"));
    }

    #[fcp_async_core::runtime::test]
    async fn rpc_cancel_self_rejects_verified_non_owner() {
        let state = cancel_route_test_state();
        state
            .cancellation
            .track_with_owner("op-self-owner", Some("user:test"));
        let token = issue_cancel_self_test_token(state.lifecycle.as_ref(), "user:other").await;
        let app = cancel_test_app(Arc::clone(&state));
        let response = send_cancel_request(
            app,
            "/rpc/cancel-self",
            serde_json::to_value(CancellationRequest {
                operation_id: "op-self-owner".to_string(),
                reason: CancelReason::UserRequested,
                cleanup: CleanupBehavior::BestEffort,
                return_partial: false,
                capability_token: Some(token),
            })
            .expect("serialize cancel-self request"),
            &[],
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read cancel-self rejection body");
        let message = String::from_utf8(body.to_vec()).expect("cancel-self rejection text");
        assert!(message.contains("cancellation principal mismatch"));
        assert!(!state.cancellation.is_cancel_requested("op-self-owner"));
    }

    #[fcp_async_core::runtime::test]
    async fn rpc_cancel_self_rejects_host_token_without_cancel_self_capability() {
        let state = cancel_route_test_state();
        state
            .cancellation
            .track_with_owner("op-self-owner", Some("user:test"));
        let token = issue_host_capability_test_token(
            state.lifecycle.as_ref(),
            CANCEL_SELF_CONNECTOR_ID,
            "cap.test.echo",
            "user:test",
            vec![CANCEL_SELF_OPERATION_ID.to_string()],
        )
        .await;
        let app = cancel_test_app(Arc::clone(&state));
        let response = send_cancel_request(
            app,
            "/rpc/cancel-self",
            serde_json::to_value(CancellationRequest {
                operation_id: "op-self-owner".to_string(),
                reason: CancelReason::UserRequested,
                cleanup: CleanupBehavior::BestEffort,
                return_partial: false,
                capability_token: Some(token),
            })
            .expect("serialize cancel-self request"),
            &[],
        )
        .await;

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read cancel-self rejection body");
        let message = String::from_utf8(body.to_vec()).expect("cancel-self rejection text");
        assert!(
            message.contains("requires `host.cancel-self` capability token"),
            "unexpected cancel-self rejection: {message}"
        );
        assert!(!state.cancellation.is_cancel_requested("op-self-owner"));
    }
}
