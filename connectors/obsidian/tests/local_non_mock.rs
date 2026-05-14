//! Local non-mock acceptance coverage for the FCP Obsidian connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::fs;

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_obsidian::connector::ObsidianConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.38";
const CAP_READ: &str = "obsidian.read";
const CAP_WRITE: &str = "obsidian.write";
const OP_BACKLINKS_GET: &str = "obsidian.backlinks.get";
const OP_HEALTH: &str = "obsidian.health";
const OP_NOTES_CREATE: &str = "obsidian.notes.create";
const OP_NOTES_GET: &str = "obsidian.notes.get";
const OP_NOTES_LIST: &str = "obsidian.notes.list";
const OP_NOTES_UPDATE: &str = "obsidian.notes.update";
const OP_SEARCH: &str = "obsidian.search";
const OP_TAGS_LIST: &str = "obsidian.tags.list";

fn seed_vault(dir: &TempDir) {
    fs::create_dir_all(dir.path().join("daily")).expect("create daily folder");
    fs::create_dir_all(dir.path().join("projects")).expect("create projects folder");
    fs::write(
        dir.path().join("daily/2026-05-14.md"),
        "# Daily Log\n\nReviewed local acceptance fixtures.\n#daily\n",
    )
    .expect("seed daily note");
    fs::write(
        dir.path().join("projects/flywheel.md"),
        "# Flywheel\n\nSee [[2026-05-14]] for acceptance status.\n#project/flywheel\n",
    )
    .expect("seed project note");
}

fn handshake_request(host_public_key: [u8; 32], instance_id: &InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [38_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static(CAP_WRITE),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    capability_id: &'static str,
    operation_id: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");

    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_id)
        .zone_id("z:work")
        .target_instance(instance_id.as_str())
        .principal("user:local-obsidian-acceptance")
        .operations(&[operation_id])
        .issuer("node:local-obsidian-acceptance")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints cbor should validate")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn invoke_request(
    operation_id: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("obsidian-local-non-mock-1"),
        connector_id: ConnectorId::from_static("fcp.obsidian"),
        operation: OperationId::from_static(operation_id),
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
        approval_tokens: vec![],
    }
}

async fn setup_connector() -> (TempDir, ObsidianConnector, Ed25519SigningKey, InstanceId) {
    let dir = tempfile::tempdir().expect("create temp vault");
    seed_vault(&dir);

    let mut connector = ObsidianConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = connector.instance_id().clone();
    connector
        .configure(json!({
            "vault_path": dir.path().to_str().expect("vault path utf8"),
            "request_timeout_ms": 10_000,
        }))
        .await
        .expect("configure connector");
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            &instance_id,
        ))
        .await
        .expect("handshake connector");

    (dir, connector, signing_key, instance_id)
}

async fn invoke_ok(
    connector: &ObsidianConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability_id: &'static str,
    operation_id: &'static str,
    input: Value,
) -> Value {
    let token = capability_token(signing_key, capability_id, operation_id, instance_id);
    let response = connector
        .invoke(invoke_request(operation_id, input, token))
        .await
        .expect("invoke through Obsidian connector");
    assert_eq!(response.status, InvokeStatus::Ok);
    response.result.expect("invoke result")
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_temp_vault_exercises_read_write_request_response_paths() {
    let (_dir, connector, signing_key, instance_id) = setup_connector().await;

    let create = invoke_ok(
        &connector,
        &signing_key,
        &instance_id,
        CAP_WRITE,
        OP_NOTES_CREATE,
        json!({
            "path": "projects/acceptance.md",
            "content": "---\ntags: [acceptance, fcp]\n---\n# Acceptance\n\nLinks [[2026-05-14]] and mentions local boundary.\n#local\n"
        }),
    )
    .await;
    assert_eq!(create["path"], "projects/acceptance.md");
    assert_eq!(create["title"], "acceptance");

    let list = invoke_ok(
        &connector,
        &signing_key,
        &instance_id,
        CAP_READ,
        OP_NOTES_LIST,
        json!({ "folder": "projects" }),
    )
    .await;
    let listed_paths = list["notes"]
        .as_array()
        .expect("listed notes")
        .iter()
        .filter_map(|note| note["path"].as_str())
        .collect::<Vec<_>>();
    assert!(listed_paths.contains(&"projects/acceptance.md"));
    assert!(listed_paths.contains(&"projects/flywheel.md"));

    let get = invoke_ok(
        &connector,
        &signing_key,
        &instance_id,
        CAP_READ,
        OP_NOTES_GET,
        json!({ "path": "projects/acceptance.md" }),
    )
    .await;
    assert_eq!(get["title"], "acceptance");
    assert!(
        get["content"]
            .as_str()
            .expect("note content")
            .contains("local boundary")
    );

    let update = invoke_ok(
        &connector,
        &signing_key,
        &instance_id,
        CAP_WRITE,
        OP_NOTES_UPDATE,
        json!({
            "path": "projects/acceptance.md",
            "content": "# Acceptance\n\nUpdated local boundary and [[flywheel]].\n#acceptance\n"
        }),
    )
    .await;
    assert_eq!(update["path"], "projects/acceptance.md");
    assert!(
        update["content"]
            .as_str()
            .expect("updated note content")
            .contains("[[flywheel]]")
    );

    let search = invoke_ok(
        &connector,
        &signing_key,
        &instance_id,
        CAP_READ,
        OP_SEARCH,
        json!({ "query": "updated local boundary" }),
    )
    .await;
    assert_eq!(search["count"], 1);
    assert_eq!(search["results"][0]["path"], "projects/acceptance.md");

    let tags = invoke_ok(
        &connector,
        &signing_key,
        &instance_id,
        CAP_READ,
        OP_TAGS_LIST,
        json!({}),
    )
    .await;
    let acceptance_tag = tags["tags"]
        .as_array()
        .expect("tags array")
        .iter()
        .find(|tag| tag["tag"] == "acceptance")
        .expect("acceptance tag present");
    assert_eq!(acceptance_tag["count"], 1);

    let backlinks = invoke_ok(
        &connector,
        &signing_key,
        &instance_id,
        CAP_READ,
        OP_BACKLINKS_GET,
        json!({ "path": "projects/flywheel.md" }),
    )
    .await;
    assert_eq!(backlinks["count"], 1);
    assert_eq!(
        backlinks["backlinks"][0]["source_path"],
        "projects/acceptance.md"
    );

    let health = invoke_ok(
        &connector,
        &signing_key,
        &instance_id,
        CAP_READ,
        OP_HEALTH,
        json!({}),
    )
    .await;
    assert_eq!(health["note_count"], 3);
    assert_eq!(health["readable"], true);
    assert_eq!(health["writable"], true);

    let artifact = json!({
        "connector": "obsidian",
        "connector_id": "fcp.obsidian",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-obsidian --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "temp_vault_filesystem",
        "provider_class": "local_sufficient",
        "operations": [
            OP_NOTES_CREATE,
            OP_NOTES_LIST,
            OP_NOTES_GET,
            OP_NOTES_UPDATE,
            OP_SEARCH,
            OP_TAGS_LIST,
            OP_BACKLINKS_GET,
            OP_HEALTH
        ],
        "request_response_boundary": {
            "storage": "local_markdown_vault",
            "vault_path_redacted": true,
            "hidden_directories_skipped": true
        },
        "auth_gate": {
            "mode": "capability_token_bound_to_instance",
            "upstream_credentials_used": false
        },
        "cleanup": "temp_vault_dropped",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rejects_path_traversal_before_leaving_temp_vault() {
    let (dir, connector, signing_key, instance_id) = setup_connector().await;
    let escaped_name = format!(
        "{}_escape.md",
        dir.path()
            .file_name()
            .expect("temp vault file name")
            .to_string_lossy()
    );
    let escaped_path = format!("../{escaped_name}");
    let outside_path = dir
        .path()
        .parent()
        .expect("temp vault parent")
        .join(&escaped_name);

    let token = capability_token(&signing_key, CAP_WRITE, OP_NOTES_CREATE, &instance_id);
    let error = connector
        .invoke(invoke_request(
            OP_NOTES_CREATE,
            json!({
                "path": escaped_path,
                "content": "# should stay outside the vault"
            }),
            token,
        ))
        .await
        .expect_err("path traversal must fail");

    match error {
        FcpError::InvalidRequest { code, message } => {
            assert_eq!(code, 1008);
            assert!(message.contains("path traversal"));
        }
        other => panic!("unexpected traversal error: {other:?}"),
    }
    assert!(!outside_path.exists());

    let artifact = json!({
        "connector": "obsidian",
        "connector_id": "fcp.obsidian",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-obsidian --test local_non_mock -- --nocapture",
        "fixture_mode": "temp_vault_filesystem",
        "provider_class": "local_sufficient",
        "operation": OP_NOTES_CREATE,
        "request_response_boundary": {
            "storage": "local_markdown_vault",
            "path_validation": "reject_parent_dir_component"
        },
        "auth_gate": {
            "mode": "capability_token_bound_to_instance",
            "upstream_credentials_used": false
        },
        "cleanup": "no_out_of_vault_file_created",
        "result": "passed"
    });
    println!("{artifact}");
}
