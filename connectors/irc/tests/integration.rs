use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_irc::{
    IrcConnector,
    types::{CAP_HEALTH_READ, CAP_MESSAGES_READ, CAP_MESSAGES_WRITE, OP_HEALTH, OP_SEND_MESSAGE},
};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, HealthState, InstanceId, InvokeRequest, OperationId, RequestId,
    ShutdownRequest, SimulateRequest, ZoneId,
};
use serde_json::{Value, json};

fn emit_test_log(event: &str, phase: &str, op_id: Option<&str>, status: &str) {
    let line = json!({
        "event": event,
        "connector": "irc",
        "phase": phase,
        "op_id": op_id,
        "status": status,
    })
    .to_string();
    eprintln!("{line}");
}

fn handshake_request(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [7u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_HEALTH_READ),
            CapabilityId::from_static(CAP_MESSAGES_READ),
            CapabilityId::from_static(CAP_MESSAGES_WRITE),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id),
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    capability: &'static str,
    operation: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

fn invoke_request(
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("irc-integration-invoke"),
        connector_id: ConnectorId::from_static("fcp.irc"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token,
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

fn simulate_request(operation: &'static str, capability_token: CapabilityToken) -> SimulateRequest {
    SimulateRequest {
        r#type: "simulate".into(),
        id: RequestId::new("irc-integration-simulate"),
        connector_id: ConnectorId::from_static("fcp.irc"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input: json!({}),
        capability_token,
        estimate_cost: false,
        check_availability: false,
        context: None,
        correlation_id: None,
    }
}

struct IrcLoopbackServer {
    port: u16,
    lines: Arc<Mutex<Vec<String>>>,
    handle: thread::JoinHandle<()>,
}

impl IrcLoopbackServer {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback IRC listener should bind");
        let port = listener
            .local_addr()
            .expect("loopback IRC listener should expose local addr")
            .port();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let captured_lines = Arc::clone(&lines);
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .expect("loopback IRC server should accept one client");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("set read timeout");
            let mut reader = BufReader::new(
                stream
                    .try_clone()
                    .expect("loopback IRC stream should be cloneable"),
            );
            let mut welcomed = false;
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
                        captured_lines
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(trimmed.clone());
                        if trimmed.starts_with("USER ") && !welcomed {
                            welcomed = true;
                            stream
                                .write_all(b":irc.test 001 testbot :welcome\r\n")
                                .expect("write welcome");
                            stream.flush().expect("flush welcome");
                        }
                        if trimmed.starts_with("QUIT ") {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            port,
            lines,
            handle,
        }
    }

    fn config(&self) -> Value {
        json!({
            "server": "127.0.0.1",
            "port": self.port,
            "nick": "testbot",
            "tls": false,
            "request_timeout_ms": 1000
        })
    }

    fn received_lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn wait_for_line(&self, expected: &str) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let lines = self.received_lines();
            if lines.iter().any(|line| line == expected) || Instant::now() >= deadline {
                return lines;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn join(self) {
        self.handle.join().expect("loopback IRC server thread");
    }
}

#[fcp_async_core::runtime::test]
async fn lifecycle_uses_requested_instance_for_bound_tokens() {
    let mut connector = IrcConnector::new();
    emit_test_log("connector_lifecycle", "configure", None, "start");
    connector
        .configure(json!({
            "server": "irc.example.test",
            "nick": "testbot",
            "tls": false,
            "request_timeout_ms": 1000
        }))
        .await
        .expect("configure should succeed");
    assert!(matches!(
        connector.health().await.status,
        HealthState::Degraded { .. }
    ));

    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    emit_test_log("connector_lifecycle", "handshake", None, "start");
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
        ))
        .await
        .expect("handshake should succeed");
    assert!(matches!(
        connector.health().await.status,
        HealthState::Ready
    ));

    let response = connector
        .simulate(simulate_request(
            OP_SEND_MESSAGE,
            capability_token(
                &signing_key,
                CAP_MESSAGES_READ,
                OP_SEND_MESSAGE,
                &instance_id,
            ),
        ))
        .await
        .expect("simulate should return a policy result");
    emit_test_log(
        "capability_check",
        "simulate",
        Some(OP_SEND_MESSAGE),
        "denied",
    );
    assert!(!response.would_succeed);
    assert_eq!(response.denial_code.as_deref(), Some("FCP-3003"));

    emit_test_log("connector_lifecycle", "shutdown", None, "start");
    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1000,
            drain: false,
            reason: Some("test complete".into()),
        })
        .await
        .expect("shutdown should succeed");
    assert!(matches!(
        connector.health().await.status,
        HealthState::Starting
    ));
}

#[fcp_async_core::runtime::test]
async fn loopback_privmsg_invoke_sends_and_quits_without_logging_message_body() {
    let server = IrcLoopbackServer::spawn();
    let mut connector = IrcConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();

    emit_test_log("connector_lifecycle", "configure", None, "start");
    connector
        .configure(server.config())
        .await
        .expect("configure should succeed");
    emit_test_log("connector_lifecycle", "handshake", None, "start");
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
        ))
        .await
        .expect("handshake should succeed");

    emit_test_log(
        "operation_invoked",
        "invoke",
        Some(OP_SEND_MESSAGE),
        "start",
    );
    let response = connector
        .invoke(invoke_request(
            OP_SEND_MESSAGE,
            json!({
                "target": "#Ops",
                "message": "hello from irc integration"
            }),
            capability_token(
                &signing_key,
                CAP_MESSAGES_WRITE,
                OP_SEND_MESSAGE,
                &instance_id,
            ),
        ))
        .await
        .expect("send should execute through the loopback server");
    emit_test_log("operation_result", "invoke", Some(OP_SEND_MESSAGE), "ok");

    let result = response.result.expect("invoke should include result");
    assert_eq!(result["status"], "sent");
    assert_eq!(result["target"], "#Ops");
    assert!(result["coordination"].is_array());

    let lines = server.wait_for_line("QUIT :fcp");
    assert!(
        lines.iter().any(|line| line == "NICK testbot"),
        "loopback server should observe IRC NICK, got {lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.starts_with("USER flywheel ")),
        "loopback server should observe IRC USER, got {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line == "PRIVMSG #Ops :hello from irc integration"),
        "loopback server should observe IRC PRIVMSG, got {lines:?}"
    );
    assert!(
        lines.iter().any(|line| line == "QUIT :fcp"),
        "loopback server should observe IRC QUIT, got {lines:?}"
    );
    server.join();
}

#[fcp_async_core::runtime::test]
async fn health_operation_reads_loopback_registration_transcript() {
    let server = IrcLoopbackServer::spawn();
    let mut connector = IrcConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();

    connector
        .configure(server.config())
        .await
        .expect("configure should succeed");
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
        ))
        .await
        .expect("handshake should succeed");

    let response = connector
        .invoke(invoke_request(
            OP_HEALTH,
            json!({}),
            capability_token(&signing_key, CAP_HEALTH_READ, OP_HEALTH, &instance_id),
        ))
        .await
        .expect("health should execute through the loopback server");
    emit_test_log("operation_result", "invoke", Some(OP_HEALTH), "ok");

    let result = response.result.expect("health should include result");
    assert_eq!(result["status"], "ok");
    assert_eq!(result["server"], "127.0.0.1");
    assert_eq!(result["tls"], false);
    assert!(
        result["manifest_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );
    assert_eq!(result["transcript"][0], ":irc.test 001 testbot :welcome");

    let lines = server.wait_for_line("QUIT :fcp");
    assert!(
        lines.iter().any(|line| line == "QUIT :fcp"),
        "loopback server should observe IRC QUIT, got {lines:?}"
    );
    server.join();
}

#[fcp_async_core::runtime::test]
async fn unconfigured_invoke_fails_closed_before_network() {
    let connector = IrcConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let error = connector
        .invoke(invoke_request(
            OP_SEND_MESSAGE,
            json!({
                "target": "#Ops",
                "message": "not sent"
            }),
            capability_token(
                &signing_key,
                CAP_MESSAGES_WRITE,
                OP_SEND_MESSAGE,
                &instance_id,
            ),
        ))
        .await
        .expect_err("unconfigured connector should fail before network");
    assert!(matches!(error, FcpError::NotConfigured));
}
