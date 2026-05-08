#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_email_generic::EmailGenericConnector;
use fcp_email_generic::client::EmailGenericClient;
use fcp_email_generic::types::EmailGenericConfig;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, HealthState,
    InstanceId, OperationId, RequestId, ShutdownRequest, SimulateRequest, ZoneId,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const CONNECTOR_ID: &str = "fcp.email-generic";
const OP_HEALTH: &str = "email_generic.health";
const OP_LIST_MAILBOXES: &str = "email_generic.list_mailboxes";
const OP_SEARCH_MESSAGES: &str = "email_generic.search_messages";
const OP_SEND_MESSAGE: &str = "email_generic.send_message";
const CAP_READ: &str = "email_generic.read";
const CAP_WRITE: &str = "email_generic.write";

#[test]
fn imap_loopback_lists_mailboxes_searches_uids_and_emits_redacted_jsonl() {
    let list_fixture = ImapFixture::start(ImapMode::Ok);
    let list_config = config_with_ports(list_fixture.port(), 2525, false, false);
    let list_client = EmailGenericClient::from_config(&list_config).expect("client config");
    let started_at = Instant::now();

    let mailboxes = list_client
        .list_mailboxes()
        .expect("LIST fixture should succeed");
    assert_eq!(mailboxes["mailboxes"], json!(["INBOX", "Archive"]));
    let list_commands = list_fixture.join();
    assert!(
        list_commands
            .iter()
            .any(|line| line.contains("LIST \"\" \"*\"")),
        "fixture should observe LIST command"
    );

    let search_fixture = ImapFixture::start(ImapMode::Ok);
    let search_config = config_with_ports(search_fixture.port(), 2525, false, false);
    let search_client = EmailGenericClient::from_config(&search_config).expect("client config");
    let search = search_client
        .search_messages("INBOX", "deploy")
        .expect("UID SEARCH fixture should succeed");
    assert_eq!(search["uids"], json!([2, 5, 8]));
    let search_commands = search_fixture.join();
    assert!(
        search_commands
            .iter()
            .any(|line| line.contains("UID SEARCH TEXT \"deploy\"")),
        "fixture should observe UID SEARCH command"
    );

    emit_fixture_log(&ProofLog {
        event: "imap_loopback",
        operation: OP_SEARCH_MESSAGES,
        capability: CAP_READ,
        zone: "z:private",
        fixture_id: "imap-ok",
        account_id_hash: hash_id("user@example.com"),
        folder_id_hash: hash_id("INBOX"),
        message_id_hash: hash_id("uid:2,5,8"),
        lifecycle_phase: "client_search",
        latency_ms: elapsed_ms(started_at),
        result: "ok",
        error_code: None,
        retry_decision: "none",
        cleanup_result: "joined",
        skip_reason: None,
    });
}

#[test]
fn smtp_loopback_sends_message_and_classifies_permanent_failure() {
    let success_fixture = SmtpFixture::start(SmtpMode::Accept);
    let success_config = config_with_ports(1993, success_fixture.port(), false, false);
    let client = EmailGenericClient::from_config(&success_config).expect("client config");
    let started_at = Instant::now();

    let sent = client
        .send_message(
            &["ops@example.com".to_owned()],
            "Deploy status",
            "Green",
            &["audit@example.com".to_owned()],
        )
        .expect("SMTP fixture should accept message");
    assert_eq!(sent["status"], "sent");
    assert_eq!(sent["to"], json!(["ops@example.com"]));
    let success_commands = success_fixture.join();
    assert!(
        success_commands
            .iter()
            .any(|line| line.starts_with("MAIL FROM:")),
        "fixture should observe MAIL FROM"
    );
    assert!(
        success_commands
            .iter()
            .any(|line| line.starts_with("RCPT TO:")),
        "fixture should observe RCPT TO"
    );
    assert!(
        success_commands.iter().any(|line| line == "DATA"),
        "fixture should observe DATA"
    );

    emit_fixture_log(&ProofLog {
        event: "smtp_loopback",
        operation: OP_SEND_MESSAGE,
        capability: CAP_WRITE,
        zone: "z:private",
        fixture_id: "smtp-accept",
        account_id_hash: hash_id("user@example.com"),
        folder_id_hash: hash_id("outbox"),
        message_id_hash: hash_id("subject:deploy-status"),
        lifecycle_phase: "client_send",
        latency_ms: elapsed_ms(started_at),
        result: "ok",
        error_code: None,
        retry_decision: "none",
        cleanup_result: "joined",
        skip_reason: None,
    });

    let failure_fixture = SmtpFixture::start(SmtpMode::PermanentFailure);
    let failure_config = config_with_ports(1993, failure_fixture.port(), false, false);
    let failure_client = EmailGenericClient::from_config(&failure_config).expect("client config");
    let error = failure_client
        .send_message(&["missing@example.com".to_owned()], "Status", "Body", &[])
        .expect_err("permanent SMTP failure should surface");
    assert!(!error.is_retryable());
    let failure_commands = failure_fixture.join();
    assert!(
        failure_commands
            .iter()
            .any(|line| line.starts_with("RCPT TO:")),
        "fixture should fail after recipient command"
    );
}

#[test]
fn smtp_starttls_mode_attempts_starttls_before_failing_closed() {
    let fixture = SmtpFixture::start(SmtpMode::StartTlsAdvertised);
    let config = config_with_ports(1993, fixture.port(), false, true);
    let client = EmailGenericClient::from_config(&config).expect("client config");

    let error = client
        .send_message(&["ops@example.com".to_owned()], "Status", "Body", &[])
        .expect_err("fixture does not complete TLS handshake");
    assert!(!error.to_string().contains("secret"));
    let commands = fixture.join();
    assert!(
        commands.iter().any(|line| line == "STARTTLS"),
        "client should attempt STARTTLS when smtp.starttls=true"
    );
}

#[fcp_async_core::runtime::test]
async fn connector_lifecycle_self_check_and_capability_denial() {
    let imap_fixture = ImapFixture::start(ImapMode::Ok);
    let smtp_fixture = SmtpFixture::start(SmtpMode::Accept);
    let mut connector = EmailGenericConnector::new();

    assert_eq!(connector.id().as_str(), CONNECTOR_ID);
    assert!(matches!(
        connector.health().await.status,
        HealthState::Degraded
    ));

    connector
        .configure(config_json(
            imap_fixture.port(),
            smtp_fixture.port(),
            false,
            false,
        ))
        .await
        .expect("configure should accept loopback config");
    assert!(matches!(
        connector.health().await.status,
        HealthState::Ready
    ));

    let self_check = connector
        .self_check()
        .await
        .expect("self-check should use loopback IMAP fixture");
    assert!(self_check.ok);
    assert_eq!(
        self_check.details.expect("self-check details")["mailbox_count"],
        2
    );

    let signing_key = Ed25519SigningKey::generate();
    connector
        .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
        .await
        .expect("handshake should accept read/write capability request");

    let denied = connector
        .simulate(SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_HEALTH),
            ZoneId::private(),
            json!({}),
            capability_token(
                &signing_key,
                &InstanceId::new(),
                CAP_READ,
                OP_HEALTH,
                &ZoneId::private(),
            ),
        ))
        .await
        .expect("simulation should return policy denial");
    assert!(!denied.would_succeed);
    assert!(
        denied
            .reason
            .as_ref()
            .is_some_and(|reason| reason.contains("instance") || reason.contains("target")),
        "denial should describe instance binding"
    );

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("email-generic integration test complete".into()),
        })
        .await
        .expect("shutdown should clear state");
    assert!(matches!(
        connector.health().await.status,
        HealthState::Degraded
    ));

    let _ = smtp_fixture.join();
    let _ = imap_fixture.join();
}

fn config_with_ports(
    imap_port: u16,
    smtp_port: u16,
    imap_tls: bool,
    smtp_starttls: bool,
) -> EmailGenericConfig {
    EmailGenericConfig::from_value(config_json(imap_port, smtp_port, imap_tls, smtp_starttls))
        .expect("loopback config should parse")
}

fn config_json(imap_port: u16, smtp_port: u16, imap_tls: bool, smtp_starttls: bool) -> Value {
    json!({
        "imap": {
            "host": "127.0.0.1",
            "port": imap_port,
            "username": "user@example.com",
            "password": "secret",
            "tls": imap_tls
        },
        "smtp": {
            "host": "127.0.0.1",
            "port": smtp_port,
            "username": "user@example.com",
            "password": "secret",
            "from_address": "user@example.com",
            "starttls": smtp_starttls
        },
        "request_timeout_ms": 2_000
    })
}

fn handshake_request(host_public_key: [u8; 32]) -> fcp_prelude::HandshakeRequest {
    fcp_prelude::HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::private(),
        zone_dir: None,
        host_public_key,
        nonce: [44_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static(CAP_WRITE),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &'static str,
    operation: &'static str,
    zone: &ZoneId,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone.as_str())
        .target_instance(instance_id.as_str())
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(raw)
}

#[derive(Clone, Copy)]
enum ImapMode {
    Ok,
}

struct ImapFixture {
    port: u16,
    commands: Arc<Mutex<Vec<String>>>,
    handle: JoinHandle<()>,
}

impl ImapFixture {
    fn start(mode: ImapMode) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind IMAP fixture");
        let port = listener.local_addr().expect("fixture addr").port();
        let commands = Arc::new(Mutex::new(Vec::new()));
        let command_log = Arc::clone(&commands);
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept IMAP client");
            handle_imap(stream, mode, command_log);
        });
        Self {
            port,
            commands,
            handle,
        }
    }

    const fn port(&self) -> u16 {
        self.port
    }

    fn join(self) -> Vec<String> {
        self.handle.join().expect("IMAP fixture should join");
        Arc::try_unwrap(self.commands)
            .expect("fixture commands should be uniquely owned")
            .into_inner()
            .expect("commands mutex should not be poisoned")
    }
}

fn handle_imap(mut stream: TcpStream, mode: ImapMode, commands: Arc<Mutex<Vec<String>>>) {
    write_response(&mut stream, "* OK fcp email generic fixture ready");
    let mut reader = BufReader::new(stream.try_clone().expect("clone IMAP stream"));
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).expect("read IMAP line") == 0 {
            break;
        }
        let command = line.trim_end_matches(['\r', '\n']).to_owned();
        commands
            .lock()
            .expect("commands lock")
            .push(command.clone());
        let tag = command.split_whitespace().next().unwrap_or("zz");

        match mode {
            ImapMode::Ok if command.contains(" LOGIN ") => {
                write_response(&mut stream, &format!("{tag} OK LOGIN completed"));
            }
            ImapMode::Ok if command.contains("LIST \"\" \"*\"") => {
                write_response(&mut stream, "* LIST (\\HasNoChildren) \"/\" \"INBOX\"");
                write_response(&mut stream, "* LIST (\\HasNoChildren) \"/\" \"Archive\"");
                write_response(&mut stream, &format!("{tag} OK LIST completed"));
            }
            ImapMode::Ok if command.contains("SELECT ") => {
                write_response(&mut stream, "* 3 EXISTS");
                write_response(&mut stream, &format!("{tag} OK SELECT completed"));
            }
            ImapMode::Ok if command.contains("UID SEARCH TEXT") => {
                write_response(&mut stream, "* SEARCH 2 5 8");
                write_response(&mut stream, &format!("{tag} OK SEARCH completed"));
            }
            ImapMode::Ok if command.contains("LOGOUT") => {
                write_response(&mut stream, "* BYE fixture closing");
                write_response(&mut stream, &format!("{tag} OK LOGOUT completed"));
                break;
            }
            ImapMode::Ok => {
                write_response(&mut stream, &format!("{tag} BAD unsupported command"));
            }
        }
    }
}

#[derive(Clone, Copy)]
enum SmtpMode {
    Accept,
    PermanentFailure,
    StartTlsAdvertised,
}

struct SmtpFixture {
    port: u16,
    commands: Arc<Mutex<Vec<String>>>,
    handle: JoinHandle<()>,
}

impl SmtpFixture {
    fn start(mode: SmtpMode) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind SMTP fixture");
        let port = listener.local_addr().expect("fixture addr").port();
        let commands = Arc::new(Mutex::new(Vec::new()));
        let command_log = Arc::clone(&commands);
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept SMTP client");
            handle_smtp(stream, mode, command_log);
        });
        Self {
            port,
            commands,
            handle,
        }
    }

    const fn port(&self) -> u16 {
        self.port
    }

    fn join(self) -> Vec<String> {
        self.handle.join().expect("SMTP fixture should join");
        Arc::try_unwrap(self.commands)
            .expect("fixture commands should be uniquely owned")
            .into_inner()
            .expect("commands mutex should not be poisoned")
    }
}

fn handle_smtp(mut stream: TcpStream, mode: SmtpMode, commands: Arc<Mutex<Vec<String>>>) {
    write_response(&mut stream, "220 fcp email generic smtp fixture");
    let mut reader = BufReader::new(stream.try_clone().expect("clone SMTP stream"));
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).expect("read SMTP line") == 0 {
            break;
        }
        let command = line.trim_end_matches(['\r', '\n']).to_owned();
        commands
            .lock()
            .expect("commands lock")
            .push(command.clone());
        let upper = command.to_ascii_uppercase();

        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            match mode {
                SmtpMode::StartTlsAdvertised => {
                    write_response(&mut stream, "250-localhost");
                    write_response(&mut stream, "250-STARTTLS");
                    write_response(&mut stream, "250 AUTH PLAIN LOGIN");
                }
                SmtpMode::Accept | SmtpMode::PermanentFailure => {
                    write_response(&mut stream, "250-localhost");
                    write_response(&mut stream, "250 AUTH PLAIN LOGIN");
                }
            }
        } else if upper == "STARTTLS" {
            write_response(&mut stream, "220 begin tls");
            break;
        } else if upper.starts_with("AUTH") {
            write_response(&mut stream, "235 authentication ok");
        } else if upper.starts_with("MAIL FROM:") {
            write_response(&mut stream, "250 sender ok");
        } else if upper.starts_with("RCPT TO:") {
            match mode {
                SmtpMode::PermanentFailure => write_response(&mut stream, "550 no such user"),
                SmtpMode::Accept | SmtpMode::StartTlsAdvertised => {
                    write_response(&mut stream, "250 recipient ok");
                }
            }
        } else if upper == "DATA" {
            write_response(&mut stream, "354 end with dot");
            read_message_data(&mut reader, &commands);
            write_response(&mut stream, "250 queued");
        } else if upper == "QUIT" {
            write_response(&mut stream, "221 bye");
            break;
        } else {
            write_response(&mut stream, "250 ok");
        }
    }
}

fn read_message_data(reader: &mut BufReader<TcpStream>, commands: &Arc<Mutex<Vec<String>>>) {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).expect("read DATA line") == 0 {
            break;
        }
        let data = line.trim_end_matches(['\r', '\n']);
        if data == "." {
            commands
                .lock()
                .expect("commands lock")
                .push("DATA_END".to_owned());
            break;
        }
    }
}

fn write_response(stream: &mut TcpStream, line: &str) {
    stream
        .write_all(format!("{line}\r\n").as_bytes())
        .expect("write fixture response");
    stream.flush().expect("flush fixture response");
}

struct ProofLog<'a> {
    event: &'a str,
    operation: &'a str,
    capability: &'a str,
    zone: &'a str,
    fixture_id: &'a str,
    account_id_hash: String,
    folder_id_hash: String,
    message_id_hash: String,
    lifecycle_phase: &'a str,
    latency_ms: u128,
    result: &'a str,
    error_code: Option<&'a str>,
    retry_decision: &'a str,
    cleanup_result: &'a str,
    skip_reason: Option<&'a str>,
}

fn emit_fixture_log(log: &ProofLog<'_>) {
    let payload = json!({
        "event": log.event,
        "command": "cargo test -p fcp-email-generic --test integration -- --nocapture",
        "git_revision": option_env!("GIT_COMMIT").unwrap_or("unknown"),
        "connector_id": CONNECTOR_ID,
        "operation_id": log.operation,
        "capability": log.capability,
        "zone": log.zone,
        "instance_id": "redacted",
        "fixture_id": log.fixture_id,
        "account_id_hash": log.account_id_hash,
        "folder_id_hash": log.folder_id_hash,
        "message_id_hash": log.message_id_hash,
        "lifecycle_phase": log.lifecycle_phase,
        "latency_ms": log.latency_ms,
        "result": log.result,
        "error_code": log.error_code,
        "retry_decision": log.retry_decision,
        "audit_receipt_id": "not_emitted",
        "cleanup_result": log.cleanup_result,
        "skip_reason": log.skip_reason,
    });
    println!(
        "EMAIL_GENERIC_FIXTURE_JSONL {}",
        serde_json::to_string(&payload).expect("proof log should serialize")
    );
}

fn hash_id(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

fn elapsed_ms(started_at: Instant) -> u128 {
    started_at.elapsed().as_millis()
}
