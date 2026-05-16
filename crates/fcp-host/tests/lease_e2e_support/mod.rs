#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityToken, CapabilityVerifier, ConnectorStateAppendOutcome,
    ConnectorStateObject, ConnectorStateStore, ConnectorStateWriteAuthorization,
    DecisionReceiptPolicy, InstanceId, ObjectHeader, ObjectId, ObjectIdKey, Provenance, Signature,
    TailscaleNodeId, ZoneId, ZonePolicyObject, ZoneTransportPolicy,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_host::{DiscoveryResponse, HostHealthResponse, HostHealthStatus};
use fcp_kernel::{ConnectorId, InvokeRequest, OperationId, RequestId};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

pub type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub const TEST_OPERATION: &str = "test.echo";
pub const TEST_CAPABILITY_ID: &str = "cap.test.echo";
pub const TEST_ADMIN_BEARER_TOKEN: &str = "host-lease-e2e-admin-bearer";
pub const HRW_LOCAL_NODE_ENV: &str = "FCP_HOST_HRW_LEASE_LOCAL_NODE";
pub const HRW_NODES_ENV: &str = "FCP_HOST_HRW_LEASE_NODES";
pub const HRW_CURRENT_SEQ_ENV: &str = "FCP_HOST_HRW_LEASE_CURRENT_SEQ";
pub const HOST_CAPABILITY_PUBLIC_KEY_ENV: &str = "FCP_HOST_CAPABILITY_PUBLIC_KEY";
pub const CONNECTOR_STATE_DIR_ENV: &str = "FCP_CONNECTOR_STATE";
pub const CONNECTOR_STATE_OBJECT_ID_KEY_ENV: &str = "FCP_CONNECTOR_STATE_OBJECT_ID_KEY";

type StderrLogs = Arc<StdMutex<Vec<String>>>;

pub struct HttpHostProcess {
    child: Child,
    pub client: reqwest::Client,
    pub base_url: String,
    #[allow(dead_code)]
    lifecycle_state_dir: tempfile::TempDir,
    #[allow(dead_code)]
    stderr_logs: StderrLogs,
    stderr_thread: Option<JoinHandle<()>>,
}

impl HttpHostProcess {
    pub async fn spawn_with_env(
        connector_configs: Vec<Value>,
        extra_env: Vec<(String, String)>,
    ) -> TestResult<Self> {
        let bind_listener = StdTcpListener::bind("127.0.0.1:0")?;
        let bind_addr = bind_listener.local_addr()?;
        drop(bind_listener);

        let base_url = format!("http://{bind_addr}");
        let lifecycle_state_dir = tempfile::tempdir()?;
        let lifecycle_state_path = lifecycle_state_dir.path().join("lifecycle-state.json");
        let zone_policies_path = write_test_zone_policies_file(&lifecycle_state_dir)?;

        let mut command = Command::new(env!("CARGO_BIN_EXE_fcp-host"));
        command
            .env("FCP_HOST_BIND", bind_addr.to_string())
            .env(
                "FCP_HOST_CONNECTORS",
                serde_json::to_string(&connector_configs)?,
            )
            .env("FCP_HOST_ADMIN_BEARER_TOKEN", TEST_ADMIN_BEARER_TOKEN)
            .env("FCP_HOST_LIFECYCLE_STATE_FILE", &lifecycle_state_path)
            .env("FCP_HOST_ZONE_POLICIES_FILE", &zone_policies_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        for (name, value) in extra_env {
            command.env(name, value);
        }

        let mut child = command.spawn()?;
        let (stderr_logs, stderr_thread) = spawn_stderr_capture(&mut child)?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;
        wait_for_host_readiness(&mut child, &client, &base_url, &stderr_logs).await?;

        Ok(Self {
            child,
            client,
            base_url,
            lifecycle_state_dir,
            stderr_logs,
            stderr_thread: Some(stderr_thread),
        })
    }

    pub async fn get_json<T>(&self, path: &str) -> TestResult<T>
    where
        T: DeserializeOwned + Send + 'static,
    {
        let response = self
            .client
            .get(format!("{}{path}", self.base_url))
            .headers(admin_headers())
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<T>().await?)
    }

    pub async fn post_json<B, T>(&self, path: &str, body: B) -> TestResult<T>
    where
        B: serde::Serialize + Send + Sync + 'static,
        T: DeserializeOwned + Send + 'static,
    {
        let response = self
            .client
            .post(format!("{}{path}", self.base_url))
            .headers(admin_headers())
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<T>().await?)
    }

    pub async fn post_json_status_text<B>(
        &self,
        path: &str,
        body: B,
    ) -> TestResult<(reqwest::StatusCode, String)>
    where
        B: serde::Serialize + Send + Sync + 'static,
    {
        let response = self
            .client
            .post(format!("{}{path}", self.base_url))
            .headers(admin_headers())
            .json(&body)
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await?;
        Ok((status, text))
    }
}

impl Drop for HttpHostProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(stderr_thread) = self.stderr_thread.take() {
            let _ = stderr_thread.join();
        }
    }
}

fn admin_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {TEST_ADMIN_BEARER_TOKEN}"))
            .expect("test bearer token must be a valid header"),
    );
    headers.insert("x-fcp-zone", HeaderValue::from_static("z:owner"));
    headers
}

fn spawn_stderr_capture(child: &mut Child) -> TestResult<(StderrLogs, JoinHandle<()>)> {
    let stderr = child.stderr.take().ok_or("fcp-host stderr was not piped")?;
    let logs = Arc::new(StdMutex::new(Vec::new()));
    let thread_logs = Arc::clone(&logs);
    let handle = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            thread_logs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(line);
        }
    });
    Ok((logs, handle))
}

async fn wait_for_host_readiness(
    child: &mut Child,
    client: &reqwest::Client,
    base_url: &str,
    stderr_logs: &StderrLogs,
) -> TestResult<()> {
    let mut last_error = None;
    let deadline = Instant::now() + Duration::from_secs(15);

    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            let raw_stderr = stderr_logs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            return Err(
                format!("fcp-host exited early with {status}; stderr: {raw_stderr:?}").into(),
            );
        }

        match fcp_async_core::time::timeout(
            Duration::from_millis(250),
            client.get(format!("{base_url}/rpc/health")).send(),
        )
        .await
        {
            Ok(Ok(response))
                if response.status().is_success()
                    || response.status() == reqwest::StatusCode::FORBIDDEN =>
            {
                return Ok(());
            }
            Ok(Ok(response)) => {
                last_error = Some(format!("health returned {}", response.status()));
                fcp_async_core::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(Err(error)) => {
                last_error = Some(error.to_string());
                fcp_async_core::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => {
                last_error = Some("health request timed out".to_string());
                fcp_async_core::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let raw_stderr = stderr_logs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Err(format!(
        "timed out waiting for fcp-host readiness; last_error: {}; stderr: {raw_stderr:?}",
        last_error.unwrap_or_else(|| "none".to_string())
    )
    .into())
}

#[allow(dead_code)]
pub async fn wait_for_host_exit(
    child: &mut Child,
    timeout: Duration,
    stderr_logs: &StderrLogs,
) -> TestResult<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let raw_stderr = stderr_logs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            return Err(format!(
                "timed out waiting for fcp-host exit after {timeout:?}; stderr: {raw_stderr:?}"
            )
            .into());
        }
        fcp_async_core::time::sleep(Duration::from_millis(25)).await;
    }
}

fn test_zone_policy(zone_id: ZoneId) -> ZonePolicyObject {
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

fn write_test_zone_policies_file(dir: &tempfile::TempDir) -> TestResult<PathBuf> {
    let policy = test_zone_policy(ZoneId::work());
    let mut policies = HashMap::new();
    policies.insert(policy.zone_id.as_str().to_string(), policy);
    let path = dir.path().join("zone-policies.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&policies)?)?;
    Ok(path)
}

pub fn capability_public_key_hex(signing_key: &Ed25519SigningKey) -> String {
    hex::encode(signing_key.verifying_key().to_bytes())
}

fn constraints_cbor_bytes() -> TestResult<Vec<u8>> {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor)?;
    Ok(cbor)
}

pub fn build_live_capability_token(
    signing_key: &Ed25519SigningKey,
    capability_id: &str,
    operation: &str,
    zone_id: &ZoneId,
) -> TestResult<CapabilityToken> {
    let now = Utc::now();
    let cbor = constraints_cbor_bytes()?;
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_id)
        .zone_id(zone_id.as_str())
        .principal("agent:lease-e2e")
        .operations(&[operation])
        .issuer("node:lease-e2e")
        .audience("*")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)?
        .sign(signing_key)?;
    Ok(CapabilityToken::from_raw(raw))
}

pub fn build_invoke_request(
    connector_id: &ConnectorId,
    signing_key: &Ed25519SigningKey,
    lease_seq: u64,
    message: &str,
) -> TestResult<InvokeRequest> {
    let zone_id = ZoneId::work();
    Ok(InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::random(),
        connector_id: connector_id.clone(),
        operation: OperationId::from_static(TEST_OPERATION),
        zone_id: zone_id.clone(),
        input: json!({ "message": message, "lease_seq": lease_seq }),
        capability_token: build_live_capability_token(
            signing_key,
            TEST_CAPABILITY_ID,
            TEST_OPERATION,
            &zone_id,
        )?,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: Some(lease_seq),
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    })
}

pub fn singleton_writer_connector_config(connector_id: &ConnectorId, name: &str) -> Value {
    singleton_writer_connector_config_with_env(connector_id, name, &[])
}

pub fn singleton_writer_connector_config_with_env(
    connector_id: &ConnectorId,
    name: &str,
    extra_env: &[(&str, String)],
) -> Value {
    let mut env = serde_json::Map::new();
    env.insert(
        "FCP_TEST_CONNECTOR_ID".to_string(),
        json!(connector_id.as_str()),
    );
    for (key, value) in extra_env {
        env.insert((*key).to_string(), json!(value));
    }

    json!({
        "id": connector_id.as_str(),
        "binary": env!("CARGO_BIN_EXE_fcp-test-connector"),
        "name": name,
        "description": "Lease E2E singleton-writer fixture",
        "config": { "state": { "model": "singleton_writer" } },
        "categories": ["test", "hrw", "lease-e2e"],
        "allowed_zones": [ZoneId::work().as_str()],
        "env": env,
    })
}

pub fn hrw_env(
    signing_key: &Ed25519SigningKey,
    local_node: &TailscaleNodeId,
    eligible_nodes: &[TailscaleNodeId],
    current_seq: Option<u64>,
) -> Vec<(String, String)> {
    let mut env = vec![
        (
            HOST_CAPABILITY_PUBLIC_KEY_ENV.to_string(),
            capability_public_key_hex(signing_key),
        ),
        (
            HRW_LOCAL_NODE_ENV.to_string(),
            local_node.as_str().to_string(),
        ),
        (HRW_NODES_ENV.to_string(), node_csv(eligible_nodes)),
    ];
    if let Some(seq) = current_seq {
        env.push((HRW_CURRENT_SEQ_ENV.to_string(), seq.to_string()));
    }
    env
}

pub fn standard_nodes() -> Vec<TailscaleNodeId> {
    ["node-a", "node-b", "node-c"]
        .into_iter()
        .map(TailscaleNodeId::new)
        .collect()
}

pub fn node_csv(nodes: &[TailscaleNodeId]) -> String {
    nodes
        .iter()
        .map(TailscaleNodeId::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

pub fn singleton_writer_subject_id(connector_id: &ConnectorId, zone_id: &ZoneId) -> ObjectId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP-HOST-SINGLETON-WRITER-HRW-LEASE-V2");
    update_len_prefixed(&mut hasher, connector_id.as_str().as_bytes());
    update_len_prefixed(&mut hasher, zone_id.as_str().as_bytes());
    ObjectId::from_bytes(*hasher.finalize().as_bytes())
}

fn update_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

pub fn selected_holder(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
    eligible_nodes: &[TailscaleNodeId],
) -> TailscaleNodeId {
    let subject_id = singleton_writer_subject_id(connector_id, zone_id);
    fcp_mesh::planner::select_lease_holder(zone_id, &subject_id, eligible_nodes)
        .expect("test node set must select an HRW holder")
}

pub fn non_holder(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
    eligible_nodes: &[TailscaleNodeId],
) -> TailscaleNodeId {
    let holder = selected_holder(connector_id, zone_id, eligible_nodes);
    eligible_nodes
        .iter()
        .find(|node| **node != holder)
        .expect("test node set must include a non-holder")
        .clone()
}

pub struct SeededConnectorState {
    pub state_root: tempfile::TempDir,
    pub root_object_id: ObjectId,
    pub head_object_id: ObjectId,
    pub object_id_key: ObjectIdKey,
    pub lease_object_id: ObjectId,
    pub lease_seq: u64,
}

pub async fn seed_connector_state(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
    object_id_key: ObjectIdKey,
    lease_object_id: ObjectId,
    seq: u64,
    lease_seq: u64,
) -> TestResult<SeededConnectorState> {
    let state_root = tempfile::tempdir()?;
    let object_store_dir =
        connector_state_canonical_object_store_dir(state_root.path(), connector_id);
    let object_store: Arc<dyn fcp_store::ObjectStore> =
        Arc::new(fcp_store::DurableObjectStore::open(
            fcp_store::DurableObjectStoreConfig::new(&object_store_dir),
        )?);
    let state_store = fcp_store::FcpStoreConnectorStateStore::new(
        Arc::clone(&object_store),
        object_id_key,
        connector_id.clone(),
        zone_id.clone(),
    )
    .with_snapshot_every_entries(0)
    .with_snapshot_every_secs(0);
    let (authorization, state_signing_key) =
        connector_state_write_authorization_for_test(connector_id, zone_id)?;
    let mut state = durable_connector_state_object(
        connector_id,
        zone_id,
        seq,
        None,
        lease_object_id,
        lease_seq,
    );
    state.sign_with(&state_signing_key)?;
    let append = state_store
        .append_object(connector_id, &authorization, state)
        .await?;
    let (head_object_id, root_object_id) = match append {
        ConnectorStateAppendOutcome::Committed {
            object_id,
            root_object_id,
            seq: committed_seq,
            snapshot_object_id,
        } => {
            assert_eq!(committed_seq, seq);
            assert_eq!(snapshot_object_id, None);
            (object_id, root_object_id)
        }
        ConnectorStateAppendOutcome::Conflict { .. } => {
            panic!("initial durable connector-state append should not conflict")
        }
    };
    drop(state_store);
    drop(object_store);

    Ok(SeededConnectorState {
        state_root,
        root_object_id,
        head_object_id,
        object_id_key,
        lease_object_id,
        lease_seq,
    })
}

fn connector_state_write_authorization_for_test(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
) -> TestResult<(ConnectorStateWriteAuthorization, Ed25519SigningKey)> {
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let constraints = CapabilityConstraints {
        resource_allow: vec![fcp_core::connector_state_resource_uri(connector_id)],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)?;
    let now = Utc::now();
    let token = CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id(fcp_core::CONNECTOR_STATE_WRITE_CAPABILITY_ID)
            .zone_id(zone_id.as_str())
            .target_instance(instance_id.as_str())
            .principal("principal:lease-e2e")
            .operations(&[fcp_core::CONNECTOR_STATE_APPEND_OPERATION_ID])
            .issuer("node:lease-e2e")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&constraints_cbor)?
            .sign(&signing_key)?,
    );
    let verifier = CapabilityVerifier::new(
        signing_key.verifying_key().to_bytes(),
        zone_id.clone(),
        instance_id,
    );
    let authorization = ConnectorStateWriteAuthorization::verify_append_token(
        &verifier,
        token,
        connector_id,
        zone_id,
    )?;
    Ok((authorization, signing_key))
}

fn durable_connector_state_object(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
    seq: u64,
    prev: Option<ObjectId>,
    lease_object_id: ObjectId,
    lease_seq: u64,
) -> ConnectorStateObject {
    let seq_byte = u8::try_from(seq).expect("test sequence should fit in CBOR byte");
    ConnectorStateObject {
        header: ObjectHeader {
            schema: fcp_store::FcpStoreConnectorStateStore::state_object_schema_id(),
            zone_id: zone_id.clone(),
            created_at: 1_800_200_000 + seq,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![lease_object_id],
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        },
        connector_id: connector_id.clone(),
        instance_id: None,
        zone_id: zone_id.clone(),
        prev,
        seq,
        state_cbor: vec![0xa1, 0x61, b'n', seq_byte],
        updated_at: 1_800_200_000 + seq,
        lease_seq,
        lease_object_id,
        writer_public_key: [0_u8; 32],
        signature: Signature::zero(),
    }
}

fn connector_state_canonical_object_store_dir(root: &Path, connector_id: &ConnectorId) -> PathBuf {
    root.join(sanitize_state_path_segment(connector_id.as_str()))
        .join("store")
        .join("objects")
}

fn sanitize_state_path_segment(value: &str) -> String {
    let segment = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if segment.is_empty() || segment == "." || segment == ".." {
        "_".to_string()
    } else {
        segment
    }
}

pub async fn assert_host_healthy(host: &HttpHostProcess) -> TestResult<()> {
    let health: HostHealthResponse = host.get_json("/rpc/health").await?;
    assert_eq!(health.status, HostHealthStatus::Healthy);
    Ok(())
}

pub async fn assert_connector_discovered(
    host: &HttpHostProcess,
    connector_id: &ConnectorId,
) -> TestResult<()> {
    let discovery: DiscoveryResponse = host.post_json("/rpc/discover", json!({})).await?;
    assert!(
        discovery
            .connectors
            .iter()
            .any(|connector| connector.id == *connector_id),
        "admitted host should discover connector {connector_id}"
    );
    Ok(())
}
