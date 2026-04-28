//! `fcp_host::doctor` enum wire-format conformance.
//!
//! `fcp doctor` is the operator self-check primitive. Four enums
//! govern its output JSON, with HETEROGENEOUS rename rules across
//! the same module — drift in any one (e.g., flipping OverallStatus
//! from UPPERCASE to lowercase) silently breaks every dashboard
//! filter and alert rule:
//!
//! - `OverallStatus` — UPPERCASE (`OK` / `WARN` / `FAIL`)
//! - `FreshnessLevel` — snake_case (`fresh` / `stale` / `too_stale`
//!   / `missing`) with `Default::default() == Fresh`
//! - `CheckStatus` — UPPERCASE (`OK` / `WARN` / `FAIL`)
//! - `CheckSeverity` — lowercase (`info` / `warning` / `critical`)
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. Each enum's variant set with the exact wire string for serde.
//! 2. Mixed-case / unknown / empty rejection for each.
//! 3. `FreshnessLevel::default == Fresh`.
//! 4. Copy + PartialEq + variant distinctness.
//! 5. **Cross-enum hetero-rename invariant**: OverallStatus and
//!    CheckStatus use UPPERCASE while CheckSeverity uses lowercase
//!    and FreshnessLevel uses snake_case — pin so a "tidy-up" PR
//!    doesn't homogenise them and break every consumer.

use fcp_host::{CheckSeverity, CheckStatus, FreshnessLevel, OverallStatus};

// ─── OverallStatus (UPPERCASE) ────────────────────────────────────

#[test]
fn overall_status_serde_uses_uppercase_for_each_variant() {
    let cases = [
        (OverallStatus::Ok, "\"OK\""),
        (OverallStatus::Warn, "\"WARN\""),
        (OverallStatus::Fail, "\"FAIL\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "{variant:?} MUST serialize as '{expected}'");
        let parsed: OverallStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn overall_status_rejects_lowercase_and_unknown() {
    for bogus in ["\"ok\"", "\"warn\"", "\"fail\"", "\"\"", "\"unknown\""] {
        assert!(
            serde_json::from_str::<OverallStatus>(bogus).is_err(),
            "OverallStatus MUST reject {bogus} (UPPERCASE only)"
        );
    }
}

#[test]
fn overall_status_three_variants_are_distinct() {
    assert_ne!(OverallStatus::Ok, OverallStatus::Warn);
    assert_ne!(OverallStatus::Ok, OverallStatus::Fail);
    assert_ne!(OverallStatus::Warn, OverallStatus::Fail);
}

#[test]
fn overall_status_implements_copy() {
    fn takes_value(_: OverallStatus) {}
    let s = OverallStatus::Warn;
    takes_value(s);
    takes_value(s);
}

// ─── FreshnessLevel (snake_case + Default) ────────────────────────

#[test]
fn freshness_level_default_is_fresh() {
    assert_eq!(
        FreshnessLevel::default(),
        FreshnessLevel::Fresh,
        "FreshnessLevel::default MUST be Fresh — fail-safe default"
    );
}

#[test]
fn freshness_level_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (FreshnessLevel::Fresh, "\"fresh\""),
        (FreshnessLevel::Stale, "\"stale\""),
        (FreshnessLevel::TooStale, "\"too_stale\""),
        (FreshnessLevel::Missing, "\"missing\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "{variant:?} MUST serialize as '{expected}'");
        let parsed: FreshnessLevel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn freshness_level_rejects_uppercase_or_camelcase_or_unknown() {
    for bogus in [
        "\"FRESH\"",
        "\"Fresh\"",
        "\"tooStale\"",
        "\"TOO_STALE\"",
        "\"\"",
        "\"expired\"",
    ] {
        assert!(
            serde_json::from_str::<FreshnessLevel>(bogus).is_err(),
            "FreshnessLevel MUST reject {bogus}"
        );
    }
}

#[test]
fn freshness_level_four_variants_are_distinct() {
    let all = [
        FreshnessLevel::Fresh,
        FreshnessLevel::Stale,
        FreshnessLevel::TooStale,
        FreshnessLevel::Missing,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn freshness_level_implements_copy() {
    fn takes_value(_: FreshnessLevel) {}
    let s = FreshnessLevel::Stale;
    takes_value(s);
    takes_value(s);
}

// ─── CheckStatus (UPPERCASE) ──────────────────────────────────────

#[test]
fn check_status_serde_uses_uppercase_for_each_variant() {
    let cases = [
        (CheckStatus::Ok, "\"OK\""),
        (CheckStatus::Warn, "\"WARN\""),
        (CheckStatus::Fail, "\"FAIL\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "{variant:?} MUST serialize as '{expected}'");
        let parsed: CheckStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn check_status_rejects_lowercase_and_unknown() {
    for bogus in ["\"ok\"", "\"warn\"", "\"fail\"", "\"\"", "\"info\""] {
        assert!(
            serde_json::from_str::<CheckStatus>(bogus).is_err(),
            "CheckStatus MUST reject {bogus} (UPPERCASE only)"
        );
    }
}

#[test]
fn check_status_three_variants_are_distinct() {
    assert_ne!(CheckStatus::Ok, CheckStatus::Warn);
    assert_ne!(CheckStatus::Ok, CheckStatus::Fail);
    assert_ne!(CheckStatus::Warn, CheckStatus::Fail);
}

#[test]
fn check_status_implements_copy() {
    fn takes_value(_: CheckStatus) {}
    let s = CheckStatus::Ok;
    takes_value(s);
    takes_value(s);
}

// ─── CheckSeverity (lowercase) ─────────────────────────────────────

#[test]
fn check_severity_serde_uses_lowercase_for_each_variant() {
    let cases = [
        (CheckSeverity::Info, "\"info\""),
        (CheckSeverity::Warning, "\"warning\""),
        (CheckSeverity::Critical, "\"critical\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "{variant:?} MUST serialize as '{expected}'");
        let parsed: CheckSeverity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn check_severity_rejects_uppercase_or_alternate_names() {
    for bogus in [
        "\"INFO\"",
        "\"Warning\"",
        "\"CRITICAL\"",
        "\"\"",
        "\"warn\"", // CheckSeverity uses 'warning' not 'warn'
    ] {
        assert!(
            serde_json::from_str::<CheckSeverity>(bogus).is_err(),
            "CheckSeverity MUST reject {bogus} (lowercase only, 'warning' not 'warn')"
        );
    }
}

#[test]
fn check_severity_three_variants_are_distinct() {
    assert_ne!(CheckSeverity::Info, CheckSeverity::Warning);
    assert_ne!(CheckSeverity::Info, CheckSeverity::Critical);
    assert_ne!(CheckSeverity::Warning, CheckSeverity::Critical);
}

#[test]
fn check_severity_implements_copy() {
    fn takes_value(_: CheckSeverity) {}
    let s = CheckSeverity::Critical;
    takes_value(s);
    takes_value(s);
}

// ─── Cross-enum hetero-rename invariant ────────────────────────────

#[test]
fn doctor_enums_use_documented_heterogeneous_rename_rules() {
    // OverallStatus + CheckStatus → UPPERCASE
    let overall_ok = serde_json::to_string(&OverallStatus::Ok).expect("serialize");
    let check_ok = serde_json::to_string(&CheckStatus::Ok).expect("serialize");
    assert_eq!(overall_ok, "\"OK\"");
    assert_eq!(check_ok, "\"OK\"");

    // CheckSeverity → lowercase ('warning' not 'warn')
    let severity_warn = serde_json::to_string(&CheckSeverity::Warning).expect("serialize");
    assert_eq!(severity_warn, "\"warning\"");

    // FreshnessLevel → snake_case ('too_stale' multi-word)
    let freshness_too_stale = serde_json::to_string(&FreshnessLevel::TooStale).expect("serialize");
    assert_eq!(freshness_too_stale, "\"too_stale\"");
}

#[test]
fn overall_status_ok_does_not_collide_with_check_severity_due_to_case() {
    // Same conceptual "ok" — but OverallStatus is UPPERCASE while
    // CheckSeverity has no Ok variant (only info/warning/critical).
    // Drift to make OverallStatus lowercase would silently make
    // dashboard filters parse wrong type.
    let overall = serde_json::to_string(&OverallStatus::Ok).expect("serialize");
    assert_eq!(overall, "\"OK\"");
    // CheckSeverity has no Ok — verify "OK" is not a valid severity.
    assert!(serde_json::from_str::<CheckSeverity>("\"OK\"").is_err());
    assert!(serde_json::from_str::<CheckSeverity>("\"ok\"").is_err());
}
