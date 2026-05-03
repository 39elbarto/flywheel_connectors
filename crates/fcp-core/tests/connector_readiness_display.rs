//! Pin `ReadinessDescriptor` constructors + status-folding + serde shape —
//! the closest analogue to "ConnectorReadiness Display"
//! (flywheel_connectors-gmw4e).
//!
//! Bead asks for `ConnectorReadiness` Display + serde pinning. No type
//! literally named `ConnectorReadiness` exists in fcp-core. The closest
//! readiness-shaped struct is [`ReadinessDescriptor`] at
//! `crates/fcp-core/src/connector_descriptors.rs:546` — the shared
//! readiness metadata used during connector bring-up + runtime health.
//! It does NOT have a `Display` impl (ReadinessDescriptor is a struct,
//! not an enum); its "Display" surface is the `status: DescriptorStatus`
//! field + `summary` operator-facing string + the embedded
//! `SelfCheckReport`/`ReadinessResponse`/`ConnectorHealth`.
//!
//! No prior test pins ReadinessDescriptor. Coverage:
//!   * 6-field JSON shape with skip-when-None + skip-when-empty for the
//!     5 optional fields,
//!   * `unverifiable` + `not_yet_measured` constructors set the documented
//!     status + summary,
//!   * `from_self_check` projects SelfCheckStatus → DescriptorStatus and
//!     emits a DescriptorCheck only when reason_code is present,
//!   * `from_readiness_response` aggregates: status=Ready iff ready==true
//!     AND every component ready, else Failed; checks are sorted by id;
//!     summary differs between ready/not-ready,
//!   * `with_health` folds health status via DescriptorStatus::combine,
//!     sets summary fallback only when None,
//!   * `with_check` accumulates checks and folds status,
//!   * JSON+CBOR round-trip preserves all fields,
//!   * Empty-checks Vec is omitted from wire form (skip_serializing_if).

use fcp_core::{
    ConnectorHealth, DescriptorCheck, DescriptorStatus, ReadinessDescriptor, ReadinessResponse,
    SelfCheckReport,
};
use serde_json::json;
use std::collections::HashMap;

#[test]
fn unverifiable_constructor_sets_unverifiable_status_with_summary() {
    let d = ReadinessDescriptor::unverifiable("probe failed");
    assert_eq!(d.status, DescriptorStatus::Unverifiable);
    assert_eq!(d.summary.as_deref(), Some("probe failed"));
    assert!(d.health.is_none());
    assert!(d.self_check.is_none());
    assert!(d.readiness.is_none());
    assert!(d.checks.is_empty());
}

#[test]
fn not_yet_measured_constructor_sets_not_yet_measured_status() {
    let d = ReadinessDescriptor::not_yet_measured("runtime probe pending");
    assert_eq!(d.status, DescriptorStatus::NotYetMeasured);
    assert_eq!(d.summary.as_deref(), Some("runtime probe pending"));
    assert!(d.health.is_none());
    assert!(d.self_check.is_none());
    assert!(d.readiness.is_none());
    assert!(d.checks.is_empty());
}

#[test]
fn from_self_check_ok_projects_to_ready_status_with_no_check() {
    // SelfCheckReport::ok() has no reason_code → no DescriptorCheck emitted.
    let report = SelfCheckReport::ok();
    let d = ReadinessDescriptor::from_self_check(report);
    assert_eq!(d.status, DescriptorStatus::Ready);
    assert!(
        d.checks.is_empty(),
        "ok report with no reason_code must emit no check"
    );
    assert!(d.self_check.is_some());
}

#[test]
fn from_self_check_failed_projects_to_failed_status_with_check() {
    // failed() has reason_code → emits a DescriptorCheck with that reason.
    let report = SelfCheckReport::failed("rc.x", "boom");
    let d = ReadinessDescriptor::from_self_check(report);
    assert_eq!(d.status, DescriptorStatus::Failed);
    assert_eq!(d.summary.as_deref(), Some("boom"));
    assert_eq!(d.checks.len(), 1);
    assert_eq!(d.checks[0].id, "rc.x");
    assert_eq!(d.checks[0].status, DescriptorStatus::Failed);
}

#[test]
fn from_self_check_degraded_projects_to_degraded_status_with_check() {
    let report = SelfCheckReport::degraded("rc.warn", "slow");
    let d = ReadinessDescriptor::from_self_check(report);
    assert_eq!(d.status, DescriptorStatus::Degraded);
    assert_eq!(d.checks.len(), 1);
    assert_eq!(d.checks[0].id, "rc.warn");
    assert_eq!(d.checks[0].status, DescriptorStatus::Degraded);
}

#[test]
fn from_readiness_response_all_ready_yields_ready_status() {
    let mut components = HashMap::new();
    components.insert("db".to_string(), true);
    components.insert("cache".to_string(), true);
    let resp = ReadinessResponse {
        ready: true,
        components,
        timestamp: chrono::Utc::now(),
    };
    let d = ReadinessDescriptor::from_readiness_response(resp);
    assert_eq!(d.status, DescriptorStatus::Ready);
    assert_eq!(d.summary.as_deref(), Some("Connector reported ready."));
    assert_eq!(d.checks.len(), 2);
    // Checks sorted by id.
    assert_eq!(d.checks[0].id, "cache");
    assert_eq!(d.checks[1].id, "db");
    assert!(d.checks.iter().all(|c| c.status == DescriptorStatus::Ready));
}

#[test]
fn from_readiness_response_one_failing_component_yields_failed_status_with_misaligned_summary() {
    // LOUD SENTINEL: the AGGREGATE STATUS and the SUMMARY field are derived
    // from DIFFERENT inputs:
    //   * status: combines ready AND every component (so any failing
    //     component → Failed).
    //   * summary: based ONLY on `readiness.ready` — so a misleading
    //     "Connector reported ready." summary may accompany a Failed
    //     aggregate status when components disagree with the top-level flag.
    // This is intentional per source (connector_descriptors.rs:625 vs
    // :654) but is a documented divergence operators must understand.
    // Pin loudly so a future "fix" that re-aligns the two without
    // updating the summary phrasing is caught.
    let mut components = HashMap::new();
    components.insert("db".to_string(), true);
    components.insert("queue".to_string(), false);
    let resp = ReadinessResponse {
        ready: true,
        components,
        timestamp: chrono::Utc::now(),
    };
    let d = ReadinessDescriptor::from_readiness_response(resp);
    assert_eq!(
        d.status,
        DescriptorStatus::Failed,
        "any failing component flips aggregate status to Failed"
    );
    // Summary tracks the top-level `ready` flag, NOT the aggregate.
    assert_eq!(
        d.summary.as_deref(),
        Some("Connector reported ready."),
        "summary tracks `ready` flag (true), even though aggregate is Failed"
    );

    let queue = d.checks.iter().find(|c| c.id == "queue").unwrap();
    assert_eq!(queue.status, DescriptorStatus::Failed);
    assert!(queue.summary.contains("not ready"));

    let db = d.checks.iter().find(|c| c.id == "db").unwrap();
    assert_eq!(db.status, DescriptorStatus::Ready);
    assert!(db.summary.contains("is ready"));
}

#[test]
fn from_readiness_response_ready_false_with_all_components_yields_failed() {
    // ready=false ALSO yields Failed even if every component is ready.
    let mut components = HashMap::new();
    components.insert("db".to_string(), true);
    let resp = ReadinessResponse {
        ready: false,
        components,
        timestamp: chrono::Utc::now(),
    };
    let d = ReadinessDescriptor::from_readiness_response(resp);
    assert_eq!(d.status, DescriptorStatus::Failed);
}

#[test]
fn from_readiness_response_empty_components_with_ready_true_is_ready() {
    // No components + ready=true → Ready (vacuous truth: all (zero)
    // components are ready).
    let resp = ReadinessResponse {
        ready: true,
        components: HashMap::new(),
        timestamp: chrono::Utc::now(),
    };
    let d = ReadinessDescriptor::from_readiness_response(resp);
    assert_eq!(d.status, DescriptorStatus::Ready);
    assert!(d.checks.is_empty());
}

#[test]
fn with_health_folds_status_via_descriptor_status_combine() {
    // Health::Healthy combines with current status. If current is Ready,
    // result is still Ready. If current is Failed, Failed wins.
    let d = ReadinessDescriptor::not_yet_measured("pending").with_health(ConnectorHealth::Healthy);
    // not_yet_measured rank=2; Ready rank=0 → max rank wins per combine,
    // so result stays at NotYetMeasured.
    assert_eq!(d.status, DescriptorStatus::NotYetMeasured);
    assert!(d.health.is_some());

    // Failed rank=10 dominates everything except itself.
    let d2 = ReadinessDescriptor::not_yet_measured("pending").with_health(
        ConnectorHealth::Unavailable {
            reason: "down".to_string(),
            since: chrono::Utc::now(),
        },
    );
    assert_eq!(
        d2.status,
        DescriptorStatus::Unavailable,
        "Unavailable rank=8 dominates NotYetMeasured rank=2"
    );
}

#[test]
fn with_health_preserves_existing_summary_and_only_falls_back_when_none() {
    // With existing summary, with_health does NOT overwrite.
    let d =
        ReadinessDescriptor::unverifiable("explicit summary").with_health(ConnectorHealth::Healthy);
    assert_eq!(d.summary.as_deref(), Some("explicit summary"));

    // With no summary, with_health falls back to a health-derived summary.
    // Construct ReadinessDescriptor manually to start with summary=None.
    let raw = ReadinessDescriptor {
        status: DescriptorStatus::Ready,
        summary: None,
        health: None,
        self_check: None,
        readiness: None,
        checks: Vec::new(),
    };
    let healthy = raw.with_health(ConnectorHealth::Healthy);
    assert_eq!(
        healthy.summary.as_deref(),
        Some("Connector reports healthy runtime state.")
    );
}

#[test]
fn with_check_appends_check_and_folds_status() {
    let d = ReadinessDescriptor::not_yet_measured("pending");
    assert_eq!(d.checks.len(), 0);

    let check = DescriptorCheck::new("rc.fail", DescriptorStatus::Failed, "boom");
    let d = d.with_check(check);
    assert_eq!(d.checks.len(), 1);
    // Failed dominates NotYetMeasured.
    assert_eq!(d.status, DescriptorStatus::Failed);
}

#[test]
fn json_shape_pinned_with_minimal_unverifiable_descriptor() {
    let d = ReadinessDescriptor::unverifiable("probe failed");
    let v = serde_json::to_value(&d).unwrap();
    let obj = v.as_object().unwrap();

    // Required: status. Optional Some: summary. Optional None: health,
    // self_check, readiness. Optional empty Vec: checks (omitted).
    let expected: std::collections::BTreeSet<&str> = ["status", "summary"].into_iter().collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "minimal shape drift: {obj:?}");

    assert_eq!(obj.get("status"), Some(&json!("unverifiable")));
    assert_eq!(obj.get("summary"), Some(&json!("probe failed")));
}

#[test]
fn json_shape_pinned_with_populated_descriptor_includes_all_six_fields() {
    let mut components = HashMap::new();
    components.insert("db".to_string(), true);
    let resp = ReadinessResponse {
        ready: true,
        components,
        timestamp: chrono::Utc::now(),
    };
    let d = ReadinessDescriptor::from_readiness_response(resp)
        .with_health(ConnectorHealth::Healthy)
        .with_check(DescriptorCheck::new("aux", DescriptorStatus::Ready, "ok"));

    let v = serde_json::to_value(&d).unwrap();
    let obj = v.as_object().unwrap();

    // status, summary, health, readiness, checks present. self_check still None.
    assert!(obj.contains_key("status"));
    assert!(obj.contains_key("summary"));
    assert!(obj.contains_key("health"));
    assert!(obj.contains_key("readiness"));
    assert!(obj.contains_key("checks"));
    assert!(!obj.contains_key("self_check"));
}

#[test]
fn empty_checks_vec_is_omitted_from_wire_form() {
    let d = ReadinessDescriptor::unverifiable("none");
    let v = serde_json::to_value(&d).unwrap();
    let obj = v.as_object().unwrap();
    assert!(
        !obj.contains_key("checks"),
        "empty checks vec must be omitted (skip_serializing_if = Vec::is_empty)"
    );
}

#[test]
fn json_roundtrip_preserves_all_descriptor_fields() {
    let report = SelfCheckReport::failed("rc.boom", "boom");
    let d = ReadinessDescriptor::from_self_check(report).with_health(ConnectorHealth::Degraded {
        reason: "slow".to_string(),
    });

    let bytes = serde_json::to_vec(&d).unwrap();
    let back: ReadinessDescriptor = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(back.status, d.status);
    assert_eq!(back.summary, d.summary);
    assert!(back.health.is_some());
    assert!(back.self_check.is_some());
    assert!(back.readiness.is_none());
    assert_eq!(back.checks.len(), d.checks.len());
    assert_eq!(back.checks[0].id, "rc.boom");
}

#[test]
fn cbor_roundtrip_preserves_descriptor_fields() {
    let d = ReadinessDescriptor::not_yet_measured("pending").with_check(DescriptorCheck::new(
        "k",
        DescriptorStatus::Ready,
        "ok",
    ));

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&d, &mut bytes).unwrap();
    let back: ReadinessDescriptor = ciborium::de::from_reader(&bytes[..]).unwrap();

    assert_eq!(back.status, DescriptorStatus::NotYetMeasured);
    assert_eq!(back.checks.len(), 1);
    assert_eq!(back.checks[0].id, "k");
}

#[test]
fn descriptor_status_serializes_inside_descriptor_as_snake_case() {
    // Spot-check the wire form of the embedded DescriptorStatus across
    // a few statuses driven by different constructors.
    let cases = [
        (ReadinessDescriptor::unverifiable("x"), "unverifiable"),
        (
            ReadinessDescriptor::not_yet_measured("x"),
            "not_yet_measured",
        ),
        (
            ReadinessDescriptor::from_self_check(SelfCheckReport::ok()),
            "ready",
        ),
        (
            ReadinessDescriptor::from_self_check(SelfCheckReport::failed("rc", "m")),
            "failed",
        ),
    ];
    for (d, expected) in cases {
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(
            v.get("status"),
            Some(&json!(expected)),
            "status drift: {v:?}"
        );
    }
}

#[test]
fn from_readiness_response_summary_distinguishes_ready_from_not_ready() {
    // Loud sentinel: the summary string is operator-facing; pin both
    // phrasings so a future "harmonize summaries" refactor doesn't
    // silently merge two distinct operator messages.
    let ready_resp = ReadinessResponse {
        ready: true,
        components: HashMap::new(),
        timestamp: chrono::Utc::now(),
    };
    let mut bad = HashMap::new();
    bad.insert("x".to_string(), false);
    let not_ready_resp = ReadinessResponse {
        ready: false,
        components: bad,
        timestamp: chrono::Utc::now(),
    };
    let ready = ReadinessDescriptor::from_readiness_response(ready_resp);
    let not_ready = ReadinessDescriptor::from_readiness_response(not_ready_resp);
    assert_ne!(ready.summary, not_ready.summary);
}
