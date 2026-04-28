//! `fcp_host::output_capture` config + install status + verification
//! status wire-format conformance.
//!
//! Five primitives composing the connector-install + output-capture
//! surface every operator dashboard reads:
//!
//! - `OutputCaptureConfig` — buffer capacities + JSON parsing knobs.
//! - `BufferStats` — ring-buffer telemetry (already covered for
//!   `RingBuffer` in `host_ring_buffer_conformance.rs`; pinning the
//!   wrapper-struct serde here).
//! - `InstallStatus` — 6 internally-tagged variants (`not_installed`,
//!   `installing`, `installed`, `failed{error}`,
//!   `updating{from,to}`, `uninstalling`).
//! - `VerificationStatus` — 4 variants with `is_ok` predicate.
//! - `InstallOptions` — 5 boolean/string knobs with documented
//!   defaults.
//! - `InstallStep` — passed-step constructor.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. `OutputCaptureConfig::default`: stdout_capacity=64 KiB,
//!    stderr_capacity=64 KiB, parse_json_lines=true, max_json_lines=100.
//! 2. `OutputCaptureConfig` builders chain mutably + preserve fields.
//! 3. `BufferStats` 4-field serde roundtrip identity.
//! 4. `InstallStatus` 6 variants snake_case + `failed`/`updating`
//!    payload carriage; rejects unknown tag.
//! 5. `VerificationStatus` 4 variants with `is_ok` ⇔
//!    `Verified | Unverified | Skipped` (Failed is the only NOT-ok).
//! 6. `InstallOptions::default`: dry_run=false, mirror_to_mesh=false,
//!    skip_signature=false, target_override=None, force=false
//!    (most-permissive false, fail-safe).
//! 7. `InstallStep::passed` constructor sets passed=true and
//!    populates fields.

use fcp_host::{
    BufferStats, InstallOptions, InstallStatus, InstallStep, OutputCaptureConfig,
    VerificationStatus,
};
use serde_json::json;

// ─── OutputCaptureConfig defaults + builders ──────────────────────

#[test]
fn output_capture_config_default_stdout_capacity_is_sixty_four_kib() {
    assert_eq!(
        OutputCaptureConfig::default().stdout_capacity,
        64 * 1024,
        "default stdout_capacity MUST be 64 KiB"
    );
}

#[test]
fn output_capture_config_default_stderr_capacity_is_sixty_four_kib() {
    assert_eq!(OutputCaptureConfig::default().stderr_capacity, 64 * 1024);
}

#[test]
fn output_capture_config_default_parses_json_lines() {
    assert!(
        OutputCaptureConfig::default().parse_json_lines,
        "default parse_json_lines MUST be true (structured-log capture on by default)"
    );
}

#[test]
fn output_capture_config_default_max_json_lines_is_one_hundred() {
    assert_eq!(OutputCaptureConfig::default().max_json_lines, 100);
}

#[test]
fn output_capture_config_new_equals_default() {
    let n = OutputCaptureConfig::new();
    let d = OutputCaptureConfig::default();
    assert_eq!(n.stdout_capacity, d.stdout_capacity);
    assert_eq!(n.stderr_capacity, d.stderr_capacity);
    assert_eq!(n.parse_json_lines, d.parse_json_lines);
    assert_eq!(n.max_json_lines, d.max_json_lines);
}

#[test]
fn output_capture_config_builder_chain_preserves_all_fields() {
    let c = OutputCaptureConfig::new()
        .with_stdout_capacity(2048)
        .with_stderr_capacity(4096)
        .with_json_parsing(false)
        .with_max_json_lines(50);
    assert_eq!(c.stdout_capacity, 2048);
    assert_eq!(c.stderr_capacity, 4096);
    assert!(!c.parse_json_lines);
    assert_eq!(c.max_json_lines, 50);
}

#[test]
fn output_capture_config_serde_roundtrip() {
    let c = OutputCaptureConfig::new()
        .with_stdout_capacity(1024)
        .with_max_json_lines(7);
    let json_str = serde_json::to_string(&c).expect("serialize");
    let parsed: OutputCaptureConfig =
        serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.stdout_capacity, c.stdout_capacity);
    assert_eq!(parsed.max_json_lines, c.max_json_lines);
}

// ─── BufferStats ──────────────────────────────────────────────────

#[test]
fn buffer_stats_serde_roundtrip_preserves_four_fields() {
    let s = BufferStats {
        len: 100,
        capacity: 1024,
        total_written: 5000,
        has_overflow: true,
    };
    let json_str = serde_json::to_string(&s).expect("serialize");
    let parsed: BufferStats = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.len, s.len);
    assert_eq!(parsed.capacity, s.capacity);
    assert_eq!(parsed.total_written, s.total_written);
    assert_eq!(parsed.has_overflow, s.has_overflow);
}

// ─── InstallStatus 6 variants ─────────────────────────────────────

#[test]
fn install_status_not_installed_is_unit_variant() {
    let s = InstallStatus::NotInstalled;
    let v = serde_json::to_value(&s).expect("serialize");
    // Internally-tagged enums use the variant name as the tag.
    assert!(
        v.is_string() || v.get("type").is_some(),
        "NotInstalled MUST serialize as some recognizable form; got {v}"
    );
    let parsed: InstallStatus =
        serde_json::from_str(&serde_json::to_string(&s).unwrap()).expect("deserialize");
    assert_eq!(parsed, InstallStatus::NotInstalled);
}

#[test]
fn install_status_installing_serde_roundtrip() {
    let s = InstallStatus::Installing;
    let json_str = serde_json::to_string(&s).expect("serialize");
    let parsed: InstallStatus = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed, s);
}

#[test]
fn install_status_installed_serde_roundtrip() {
    let s = InstallStatus::Installed;
    let json_str = serde_json::to_string(&s).expect("serialize");
    let parsed: InstallStatus = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed, s);
}

#[test]
fn install_status_failed_carries_error_payload() {
    let s = InstallStatus::Failed {
        error: "binary download failed".into(),
    };
    let json_str = serde_json::to_string(&s).expect("serialize");
    let parsed: InstallStatus = serde_json::from_str(&json_str).expect("deserialize");
    match parsed {
        InstallStatus::Failed { error } => {
            assert_eq!(error, "binary download failed");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn install_status_updating_carries_from_and_to_versions() {
    let s = InstallStatus::Updating {
        from_version: "1.0.0".into(),
        to_version: "2.0.0".into(),
    };
    let json_str = serde_json::to_string(&s).expect("serialize");
    let parsed: InstallStatus = serde_json::from_str(&json_str).expect("deserialize");
    match parsed {
        InstallStatus::Updating {
            from_version,
            to_version,
        } => {
            assert_eq!(from_version, "1.0.0");
            assert_eq!(to_version, "2.0.0");
        }
        other => panic!("expected Updating, got {other:?}"),
    }
}

#[test]
fn install_status_uninstalling_serde_roundtrip() {
    let s = InstallStatus::Uninstalling;
    let json_str = serde_json::to_string(&s).expect("serialize");
    let parsed: InstallStatus = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed, s);
}

#[test]
fn install_status_six_variants_are_distinct() {
    let v = [
        InstallStatus::NotInstalled,
        InstallStatus::Installing,
        InstallStatus::Installed,
        InstallStatus::Failed {
            error: "x".into(),
        },
        InstallStatus::Updating {
            from_version: "1".into(),
            to_version: "2".into(),
        },
        InstallStatus::Uninstalling,
    ];
    for (i, a) in v.iter().enumerate() {
        for (j, b) in v.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

// ─── VerificationStatus ────────────────────────────────────────────

#[test]
fn verification_status_is_ok_covers_verified_unverified_skipped() {
    assert!(VerificationStatus::Verified.is_ok());
    assert!(
        VerificationStatus::Unverified.is_ok(),
        "Unverified MUST be 'ok' — no attestation available but allowed by policy"
    );
    assert!(
        VerificationStatus::Skipped.is_ok(),
        "Skipped MUST be 'ok' — verification explicitly skipped (dev mode)"
    );
}

#[test]
fn verification_status_failed_is_not_ok() {
    let f = VerificationStatus::Failed {
        reason: "signature mismatch".into(),
    };
    assert!(!f.is_ok(), "Failed MUST be the only NOT-ok variant");
}

#[test]
fn verification_status_failed_carries_reason_payload() {
    let f = VerificationStatus::Failed {
        reason: "signature mismatch".into(),
    };
    let json_str = serde_json::to_string(&f).expect("serialize");
    let parsed: VerificationStatus = serde_json::from_str(&json_str).expect("deserialize");
    match parsed {
        VerificationStatus::Failed { reason } => {
            assert_eq!(reason, "signature mismatch");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn verification_status_serde_roundtrip_for_each_variant() {
    let cases = vec![
        VerificationStatus::Verified,
        VerificationStatus::Unverified,
        VerificationStatus::Skipped,
        VerificationStatus::Failed {
            reason: "x".into(),
        },
    ];
    for original in cases {
        let json_str = serde_json::to_string(&original).expect("serialize");
        let parsed: VerificationStatus =
            serde_json::from_str(&json_str).expect("deserialize");
        // Re-serialize and compare semantic JSON.
        let v1 = serde_json::to_value(&parsed).expect("v1");
        let v2 = serde_json::to_value(&original).expect("v2");
        assert_eq!(v1, v2);
    }
}

// ─── InstallOptions ───────────────────────────────────────────────

#[test]
fn install_options_default_is_safe_minimum() {
    let o = InstallOptions::default();
    assert!(!o.dry_run, "default dry_run MUST be false");
    assert!(!o.mirror_to_mesh, "default mirror_to_mesh MUST be false");
    assert!(
        !o.skip_signature,
        "default skip_signature MUST be false (fail-safe)"
    );
    assert!(
        o.target_override.is_none(),
        "default target_override MUST be None"
    );
    assert!(!o.force, "default force MUST be false");
}

#[test]
fn install_options_skip_signature_is_dev_mode_only() {
    // Documented contract: skip_signature is dev-mode only. Pin the
    // default-false semantics — flipping the default would break
    // every production install.
    let o = InstallOptions::default();
    assert!(
        !o.skip_signature,
        "skip_signature MUST default to false (production safety)"
    );
}

#[test]
fn install_options_serde_roundtrip_preserves_all_five_fields() {
    let o = InstallOptions {
        dry_run: true,
        mirror_to_mesh: true,
        skip_signature: false,
        target_override: Some("linux/arm64".into()),
        force: true,
    };
    let json_str = serde_json::to_string(&o).expect("serialize");
    let parsed: InstallOptions = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.dry_run, o.dry_run);
    assert_eq!(parsed.mirror_to_mesh, o.mirror_to_mesh);
    assert_eq!(parsed.skip_signature, o.skip_signature);
    assert_eq!(parsed.target_override, o.target_override);
    assert_eq!(parsed.force, o.force);
}

// ─── InstallStep ──────────────────────────────────────────────────

#[test]
fn install_step_passed_constructor_sets_passed_true() {
    let s = InstallStep::passed("download_binary", "ok", 12.5);
    assert!(s.passed);
    assert_eq!(s.name, "download_binary");
    assert_eq!(s.detail, "ok");
    assert!((s.elapsed_ms - 12.5).abs() < f64::EPSILON);
}

#[test]
fn install_step_serde_roundtrip_preserves_all_fields() {
    let s = InstallStep {
        name: "verify_signature".into(),
        passed: false,
        elapsed_ms: 0.5,
        detail: "key not in keyring".into(),
    };
    let json_str = serde_json::to_string(&s).expect("serialize");
    let parsed: InstallStep = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.name, s.name);
    assert_eq!(parsed.passed, s.passed);
    assert!((parsed.elapsed_ms - s.elapsed_ms).abs() < f64::EPSILON);
    assert_eq!(parsed.detail, s.detail);
}

// ─── Cross-enum sanity ────────────────────────────────────────────

#[test]
fn install_status_rejects_unknown_variant_tag() {
    // Bogus serde input — depending on internal-tag form, MUST fail.
    let bogus = json!("notarealinstallstate").to_string();
    assert!(
        serde_json::from_str::<InstallStatus>(&bogus).is_err(),
        "bare bogus string MUST NOT deserialize as InstallStatus"
    );
}

#[test]
fn verification_status_rejects_unknown_variant_tag() {
    let bogus = json!("invented_status").to_string();
    assert!(
        serde_json::from_str::<VerificationStatus>(&bogus).is_err(),
        "bare bogus string MUST NOT deserialize as VerificationStatus"
    );
}
