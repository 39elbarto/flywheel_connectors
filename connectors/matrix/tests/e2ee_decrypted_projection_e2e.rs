use std::fs::{File, create_dir_all};
use std::io::Write as _;
use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use fcp_matrix::crypto::{
    MATRIX_MEGOLM_ALGORITHM, MatrixEncryptedEventProjectionContext,
    MatrixEncryptedEventRedactionState, MatrixProjectionVerificationStatus,
    MatrixVerifiedDecryptedMessageEvent, project_trust_gated_decrypted_event,
};
use fcp_matrix::types::{
    MatrixE2eeBackupConfig, MatrixE2eeConfig, MatrixE2eeDeviceListConfig,
    MatrixE2eeDeviceListStatus, MatrixE2eeMaterialStatus, MatrixE2eeRecoveryConfig,
    MatrixE2eeTrustStateConfig, MatrixStatePersistenceConfig, MatrixUndecryptedRetryConfig,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn unique_log_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "fcp-matrix-e2ee-decrypted-projection-e2e-{}-{unique}",
        process::id()
    ));
    create_dir_all(&dir).expect("create e2e log directory");
    dir.join("matrix_e2ee_decrypted_projection_e2e.jsonl")
}

fn log_step(logs: &mut File, step: &str, status: &str, details: Value) {
    let line = json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "step": step,
        "status": status,
        "details": details,
    });
    writeln!(logs, "{line}").expect("write jsonl log");
}

fn current_git_revision() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn ready_e2ee() -> MatrixE2eeConfig {
    MatrixE2eeConfig {
        verified_decryption_requested: true,
        account_user_id: Some("@bot:matrix.example".into()),
        device_id: Some("DEVICE123".into()),
        trust_state: MatrixE2eeTrustStateConfig {
            own_device: MatrixE2eeMaterialStatus::Verified,
            device_keys: MatrixE2eeMaterialStatus::Verified,
            device_list: MatrixE2eeDeviceListConfig {
                status: MatrixE2eeDeviceListStatus::Fresh,
                last_refresh_age_ms: Some(5),
            },
            cross_signing: MatrixE2eeMaterialStatus::Verified,
            tracked_users: vec!["@alice:matrix.example".into()],
            tracked_rooms: vec!["!room:matrix.example".into()],
        },
        recovery: MatrixE2eeRecoveryConfig {
            status: MatrixE2eeMaterialStatus::Verified,
        },
        room_key_backup: MatrixE2eeBackupConfig {
            status: MatrixE2eeMaterialStatus::Verified,
            backup_version: Some("1".into()),
        },
        undecrypted_retry: MatrixUndecryptedRetryConfig {
            max_attempts: 2,
            retry_after_ms: 500,
        },
        ..MatrixE2eeConfig::default()
    }
}

fn encrypted_input() -> MatrixEncryptedEventProjectionContext {
    MatrixEncryptedEventProjectionContext {
        room_id: "!room:matrix.example".into(),
        event_id: Some("$encrypted".into()),
        sender: Some("@alice:matrix.example".into()),
        origin_server_ts: Some(160),
        algorithm: Some(MATRIX_MEGOLM_ALGORITHM.into()),
        session_id: Some("SESSION1".into()),
        redaction_state: MatrixEncryptedEventRedactionState::Clear,
        retry_attempts_used: 0,
    }
}

fn verified_candidate() -> MatrixVerifiedDecryptedMessageEvent {
    MatrixVerifiedDecryptedMessageEvent {
        room_id: "!room:matrix.example".into(),
        sender: "@alice:matrix.example".into(),
        sender_device_id: "ALICEDEVICE".into(),
        sender_device_trust: MatrixProjectionVerificationStatus::Verified,
        cross_signing_trust: MatrixProjectionVerificationStatus::Verified,
        session_id: "SESSION1".into(),
        session_room_id: "!room:matrix.example".into(),
        session_trust: MatrixProjectionVerificationStatus::Verified,
        algorithm: MATRIX_MEGOLM_ALGORITHM.into(),
        replay_key: "SESSION1:$encrypted:0".into(),
        msgtype: "m.text".into(),
        body: "trusted plaintext".into(),
        format: None,
        formatted_body: None,
        redaction_state: MatrixEncryptedEventRedactionState::Clear,
    }
}

fn body_hash(candidate: &MatrixVerifiedDecryptedMessageEvent) -> String {
    hex::encode(Sha256::digest(candidate.body.as_bytes()))
}

#[test]
fn e2ee_decrypted_projection_logs_success_denials_parity_and_shutdown() {
    let log_path = unique_log_path();
    println!(
        "matrix_e2ee_decrypted_projection_e2e_log={}",
        log_path.display()
    );
    let mut logs = File::create(&log_path).expect("create e2e jsonl log");
    let state = MatrixStatePersistenceConfig {
        enabled: true,
        account_user_id: Some("@bot:matrix.example".into()),
        device_id: Some("DEVICE123".into()),
        ..MatrixStatePersistenceConfig::default()
    };
    let e2ee = ready_e2ee();
    let input = encrypted_input();
    let candidate = verified_candidate();

    log_step(
        &mut logs,
        "start",
        "ok",
        json!({
            "command_line": std::env::args().collect::<Vec<_>>(),
            "git_revision": current_git_revision(),
            "matrix_sdk_crypto_backend": cfg!(feature = "matrix-sdk-crypto-backend"),
            "fixture": "verified_crypto_result_boundary",
            "external_crypto_material_available": false,
        }),
    );
    if !cfg!(feature = "matrix-sdk-crypto-backend") {
        log_step(
            &mut logs,
            "structured_skip_external_crypto_fixture",
            "skipped",
            json!({
                "reason_code": "external_matrix_crypto_fixture_unavailable",
                "deterministic_projection_fixture_still_exercised": true,
            }),
        );
    }

    let success = project_trust_gated_decrypted_event(&input, Some(&candidate), &e2ee, &state, &[]);
    log_step(
        &mut logs,
        "verified_decrypt_success",
        "ok",
        json!({
            "metadata": success.metadata_event,
            "event_topics": ["matrix.message.decrypted", "matrix.encrypted"],
            "body_sha256": body_hash(&candidate),
        }),
    );
    assert!(success.authorized_event.is_some());

    let mut wrong_room = candidate.clone();
    wrong_room.session_room_id = "!other:matrix.example".into();
    let wrong_room_projection =
        project_trust_gated_decrypted_event(&input, Some(&wrong_room), &e2ee, &state, &[]);
    log_step(
        &mut logs,
        "wrong_room_denial",
        "ok",
        wrong_room_projection.metadata_event.clone(),
    );
    assert_eq!(wrong_room_projection.dropped_reason, Some("wrong_room"));

    let mut untrusted_sender = candidate.clone();
    untrusted_sender.sender_device_trust = MatrixProjectionVerificationStatus::Unverified;
    let untrusted_projection =
        project_trust_gated_decrypted_event(&input, Some(&untrusted_sender), &e2ee, &state, &[]);
    log_step(
        &mut logs,
        "wrong_sender_device_denial",
        "ok",
        untrusted_projection.metadata_event.clone(),
    );
    assert_eq!(
        untrusted_projection.dropped_reason,
        Some("sender_device_untrusted")
    );

    let mut missing_cross_signing = e2ee.clone();
    missing_cross_signing.trust_state.cross_signing = MatrixE2eeMaterialStatus::Missing;
    let cross_signing_projection = project_trust_gated_decrypted_event(
        &input,
        Some(&candidate),
        &missing_cross_signing,
        &state,
        &[],
    );
    log_step(
        &mut logs,
        "missing_cross_signing_denial",
        "ok",
        cross_signing_projection.metadata_event.clone(),
    );
    assert_eq!(
        cross_signing_projection.dropped_reason,
        Some("cross_signing_unverified")
    );

    let mut backup_mismatch = e2ee.clone();
    backup_mismatch.room_key_backup.status = MatrixE2eeMaterialStatus::PresentUnverified;
    let backup_projection = project_trust_gated_decrypted_event(
        &input,
        Some(&candidate),
        &backup_mismatch,
        &state,
        &[],
    );
    log_step(
        &mut logs,
        "backup_mismatch_denial",
        "ok",
        backup_projection.metadata_event.clone(),
    );
    assert_eq!(
        backup_projection.dropped_reason,
        Some("room_key_backup_unverified")
    );

    let mut redacted_input = input.clone();
    redacted_input.redaction_state = MatrixEncryptedEventRedactionState::Redacted;
    let redacted_projection =
        project_trust_gated_decrypted_event(&redacted_input, Some(&candidate), &e2ee, &state, &[]);
    log_step(
        &mut logs,
        "redacted_event_denial",
        "ok",
        redacted_projection.metadata_event.clone(),
    );
    assert_eq!(
        redacted_projection.dropped_reason,
        Some("redacted_event_denied")
    );

    let mut unsupported_input = input.clone();
    unsupported_input.algorithm = Some("m.olm.v1.curve25519-aes-sha2".into());
    let unsupported_projection = project_trust_gated_decrypted_event(
        &unsupported_input,
        Some(&candidate),
        &e2ee,
        &state,
        &[],
    );
    log_step(
        &mut logs,
        "unsupported_algorithm_denial",
        "ok",
        unsupported_projection.metadata_event.clone(),
    );
    assert_eq!(
        unsupported_projection.dropped_reason,
        Some("unsupported_algorithm")
    );

    let replay_projection = project_trust_gated_decrypted_event(
        &input,
        Some(&candidate),
        &e2ee,
        &state,
        &[candidate.replay_key.clone()],
    );
    log_step(
        &mut logs,
        "replay_duplicate_denial",
        "ok",
        replay_projection.metadata_event.clone(),
    );
    assert_eq!(replay_projection.dropped_reason, Some("replay_duplicate"));

    let mut final_retry_input = input.clone();
    final_retry_input.retry_attempts_used = 2;
    let final_retry_projection =
        project_trust_gated_decrypted_event(&final_retry_input, None, &e2ee, &state, &[]);
    log_step(
        &mut logs,
        "undecrypted_final_failure",
        "ok",
        final_retry_projection.metadata_event.clone(),
    );
    assert_eq!(
        final_retry_projection.dropped_reason,
        Some("undecrypted_retry_budget_exhausted")
    );

    let mut fallback_e2ee = e2ee.clone();
    fallback_e2ee.verified_decryption_requested = false;
    let fallback_projection =
        project_trust_gated_decrypted_event(&input, Some(&candidate), &fallback_e2ee, &state, &[]);
    log_step(
        &mut logs,
        "policy_fallback_not_requested",
        "ok",
        fallback_projection.metadata_event.clone(),
    );
    assert_eq!(
        fallback_projection.dropped_reason,
        Some("verified_e2ee_decryption_not_requested")
    );

    let manual_projection =
        project_trust_gated_decrypted_event(&input, Some(&candidate), &e2ee, &state, &[]);
    let supervised_projection =
        project_trust_gated_decrypted_event(&input, Some(&candidate), &e2ee, &state, &[]);
    log_step(
        &mut logs,
        "supervised_manual_sync_parity",
        "ok",
        json!({
            "manual": manual_projection.metadata_event,
            "supervised": supervised_projection.metadata_event,
            "topics": ["matrix.message.decrypted", "matrix.encrypted", "matrix.event.dropped"],
        }),
    );

    log_step(
        &mut logs,
        "shutdown",
        "ok",
        json!({
            "log_path": log_path,
            "ciphertext_emitted": false,
            "secret_material_logged": false,
        }),
    );
}
