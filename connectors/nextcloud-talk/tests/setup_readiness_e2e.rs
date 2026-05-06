use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;

use fcp_nextcloud_talk::NextcloudTalkConnector;
use fcp_prelude::{FcpConnector, SelfCheckStatus, ShutdownRequest};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct LoopbackCapabilitiesServer {
    base_url: String,
    join: thread::JoinHandle<()>,
}

impl LoopbackCapabilitiesServer {
    fn spawn(has_talk: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback server");
        let addr = listener.local_addr().expect("loopback server addr");
        let body = capabilities_body(has_talk);
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept loopback request");
            let mut buffer = [0_u8; 1024];
            let bytes_read = stream.read(&mut buffer).expect("read loopback request");
            let request = String::from_utf8_lossy(&buffer[..bytes_read]);
            assert!(
                request.starts_with("GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1"),
                "unexpected request: {request}"
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write loopback response");
        });
        Self {
            base_url: format!("http://{addr}"),
            join,
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(self) {
        self.join.join().expect("loopback server thread");
    }
}

fn capabilities_body(has_talk: bool) -> String {
    let capabilities = if has_talk {
        json!({
            "spreed": {
                "features": ["chat-read-marker", "reactions"],
                "config": {
                    "chat": {
                        "max-length": 32000
                    }
                }
            }
        })
    } else {
        json!({})
    };
    json!({
        "ocs": {
            "meta": {
                "status": "ok",
                "statuscode": 100,
                "message": "OK"
            },
            "data": {
                "version": {
                    "major": 29,
                    "minor": 0,
                    "micro": 0,
                    "string": "29.0.0"
                },
                "capabilities": capabilities
            }
        }
    })
    .to_string()
}

fn git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn hash_label(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("sha256:{}", &digest[..16])
}

fn doctor_check<'a>(doctor: &'a Value, name: &str) -> &'a Value {
    doctor["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|check| check["name"] == name))
        .unwrap_or(&Value::Null)
}

fn readiness_warnings(doctor: &Value) -> Vec<String> {
    doctor["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|check| check["passed"] == false && check["critical"] == false)
        .filter_map(|check| check["message"].as_str().map(ToOwned::to_owned))
        .collect()
}

fn evidence_record(
    scenario: &str,
    account_id: &str,
    doctor: Option<&Value>,
    self_check: Option<&Value>,
    skip_reason: Option<&str>,
) -> Value {
    let server_url = doctor.map(|value| doctor_check(value, "server_url"));
    json!({
        "record_type": "nextcloud_talk_setup_readiness_e2e",
        "scenario": scenario,
        "command_line": std::env::args().collect::<Vec<_>>().join(" "),
        "git_revision": git_revision(),
        "account_id_hash": hash_label(account_id),
        "credential_source": {
            "ocs": doctor
                .map_or_else(
                    || Value::String("not_configured".to_string()),
                    |value| doctor_check(value, "ocs_auth_source")["details"]["mode"].clone(),
                ),
            "webhook_bot_secret": doctor
                .map_or_else(
                    || Value::String("not_configured".to_string()),
                    |value| {
                        doctor_check(value, "webhook_readiness")["details"]["bot_secret_source"]
                            .clone()
                    },
                ),
        },
        "url_class": server_url
            .map_or(Value::Null, |check| check["details"]["classification"].clone()),
        "network_constraints_decision": server_url.map_or_else(
            || json!({ "allowed": false, "reason": "configuration rejected" }),
            |check| json!({
                "allowed": check["details"]["allowed"],
                "reason": check["details"]["reason"],
                "constraints": check["details"]["network_constraints"],
            }),
        ),
        "doctor_status": doctor.map_or(Value::Bool(false), |value| value["passed"].clone()),
        "self_check_status": self_check
            .map_or(Value::Null, |value| value["status"].clone()),
        "readiness_warnings": doctor.map_or_else(Vec::new, readiness_warnings),
        "clean_shutdown": self_check.is_some(),
        "skip_reason": skip_reason,
    })
}

fn encode_jsonl(records: &[Value]) -> String {
    records
        .iter()
        .map(|record| serde_json::to_string(record).expect("serialize evidence record"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn maybe_write_jsonl(jsonl: &str) {
    if let Some(path) = std::env::var_os("NEXTCLOUD_TALK_SETUP_READINESS_JSONL_OUT") {
        std::fs::write(path, jsonl).expect("write setup readiness JSONL");
    }
}

#[fcp_async_core::runtime::test]
async fn setup_readiness_no_mock_loopback_evidence_jsonl() {
    let mut records = Vec::new();

    let ready_server = LoopbackCapabilitiesServer::spawn(true);
    let mut ready = NextcloudTalkConnector::new();
    ready
        .configure(json!({
            "server_url": ready_server.base_url(),
            "account_id": "work",
            "account_name": "Work Talk",
            "auth": {
                "mode": "credential_id",
                "credential_id": "ocs_cred"
            },
            "webhook": {
                "enabled": true,
                "bot_secret": {
                    "source": "credential_id",
                    "credential_id": "bot_cred"
                },
                "backend_allowlist": [ready_server.base_url()]
            },
            "inbound_policy": {
                "dm_policy": "allowlist",
                "allow_from": ["alice"],
                "rooms": ["engineering"]
            },
            "network": {
                "allow_private_networks": true
            }
        }))
        .await
        .expect("ready configure");
    let ready_doctor = serde_json::to_value(ready.doctor()).expect("ready doctor");
    let ready_self_check =
        serde_json::to_value(ready.self_check().await.expect("ready self_check"))
            .expect("ready self_check json");
    assert_eq!(ready_self_check["status"], json!(SelfCheckStatus::Ok));
    ready
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("setup readiness e2e".into()),
        })
        .await
        .expect("ready shutdown");
    ready_server.join();
    records.push(evidence_record(
        "configured_ocs_auth_webhook_secret_private_allowed",
        "work",
        Some(&ready_doctor),
        Some(&ready_self_check),
        None,
    ));

    let missing_talk_server = LoopbackCapabilitiesServer::spawn(false);
    let mut missing_talk = NextcloudTalkConnector::new();
    missing_talk
        .configure(json!({
            "server_url": missing_talk_server.base_url(),
            "account_id": "lab",
            "auth": {
                "mode": "credential_id",
                "credential_id": "ocs_cred"
            },
            "network": {
                "allow_private_networks": true
            }
        }))
        .await
        .expect("missing Talk configure");
    let missing_talk_doctor =
        serde_json::to_value(missing_talk.doctor()).expect("missing Talk doctor");
    let missing_talk_self_check = serde_json::to_value(
        missing_talk
            .self_check()
            .await
            .expect("missing Talk self_check"),
    )
    .expect("missing Talk self_check json");
    assert_eq!(
        missing_talk_self_check["status"],
        json!(SelfCheckStatus::Failed)
    );
    missing_talk_server.join();
    records.push(evidence_record(
        "missing_talk_capability",
        "lab",
        Some(&missing_talk_doctor),
        Some(&missing_talk_self_check),
        None,
    ));

    let private_blocked = NextcloudTalkConnector::new()
        .configure(json!({
            "server_url": "http://127.0.0.1:8788",
            "account_id": "blocked",
            "auth": {
                "mode": "credential_id",
                "credential_id": "ocs_cred"
            }
        }))
        .await
        .expect_err("private URL must be blocked by default");
    assert!(
        private_blocked
            .to_string()
            .contains("network.allow_private_networks=true")
    );
    records.push(evidence_record(
        "private_network_blocked_without_opt_in",
        "blocked",
        None,
        None,
        Some("configuration rejected by network policy"),
    ));

    let malformed_url = NextcloudTalkConnector::new()
        .configure(json!({
            "server_url": "not a url",
            "account_id": "malformed",
            "auth": {
                "mode": "credential_id",
                "credential_id": "ocs_cred"
            }
        }))
        .await
        .expect_err("malformed URL must be rejected");
    assert!(malformed_url.to_string().contains("Invalid server_url"));
    records.push(evidence_record(
        "malformed_url_rejected",
        "malformed",
        None,
        None,
        Some("configuration rejected by URL parser"),
    ));

    let mut webhook_gap = NextcloudTalkConnector::new();
    webhook_gap
        .configure(json!({
            "server_url": "https://cloud.example.com",
            "account_id": "webhook-gap",
            "auth": {
                "mode": "credential_id",
                "credential_id": "ocs_cred"
            },
            "webhook": {
                "enabled": true
            }
        }))
        .await
        .expect("webhook gap configure");
    let webhook_gap_doctor =
        serde_json::to_value(webhook_gap.doctor()).expect("webhook gap doctor");
    assert!(
        readiness_warnings(&webhook_gap_doctor)
            .iter()
            .any(|warning| warning.contains("bot secret is missing"))
    );
    records.push(evidence_record(
        "webhook_credential_gap_warning",
        "webhook-gap",
        Some(&webhook_gap_doctor),
        None,
        Some("self_check skipped; public fixture URL intentionally not contacted"),
    ));

    let jsonl = encode_jsonl(&records);
    assert!(!jsonl.trim().is_empty());
    assert!(!jsonl.contains("bot_cred"));
    assert!(!jsonl.contains("ocs_cred"));
    for line in jsonl.lines() {
        let value: Value = serde_json::from_str(line).expect("JSONL line should parse");
        assert_eq!(value["record_type"], "nextcloud_talk_setup_readiness_e2e");
        assert!(
            value["command_line"]
                .as_str()
                .is_some_and(|line| !line.is_empty())
        );
        assert!(
            value["git_revision"]
                .as_str()
                .is_some_and(|rev| !rev.is_empty())
        );
        assert!(
            value["account_id_hash"]
                .as_str()
                .is_some_and(|hash| hash.starts_with("sha256:"))
        );
        assert!(value.get("network_constraints_decision").is_some());
        assert!(value.get("skip_reason").is_some());
    }
    maybe_write_jsonl(&jsonl);
}
