#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_host::{
    AuditStatus, CheckResult, CheckSeverity, CheckStatus, CheckpointStatus, DegradedModeStatus,
    FreshnessLevel, RevocationStatus, StoreCoverageStatus, TransportPolicyStatus,
};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzFreshnessLevel {
    Fresh,
    Stale,
    TooStale,
    Missing,
}

impl From<FuzzFreshnessLevel> for FreshnessLevel {
    fn from(value: FuzzFreshnessLevel) -> Self {
        match value {
            FuzzFreshnessLevel::Fresh => Self::Fresh,
            FuzzFreshnessLevel::Stale => Self::Stale,
            FuzzFreshnessLevel::TooStale => Self::TooStale,
            FuzzFreshnessLevel::Missing => Self::Missing,
        }
    }
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzCheckStatus {
    Ok,
    Warn,
    Fail,
}

impl From<FuzzCheckStatus> for CheckStatus {
    fn from(value: FuzzCheckStatus) -> Self {
        match value {
            FuzzCheckStatus::Ok => Self::Ok,
            FuzzCheckStatus::Warn => Self::Warn,
            FuzzCheckStatus::Fail => Self::Fail,
        }
    }
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzCheckSeverity {
    Info,
    Warning,
    Critical,
}

impl From<FuzzCheckSeverity> for CheckSeverity {
    fn from(value: FuzzCheckSeverity) -> Self {
        match value {
            FuzzCheckSeverity::Info => Self::Info,
            FuzzCheckSeverity::Warning => Self::Warning,
            FuzzCheckSeverity::Critical => Self::Critical,
        }
    }
}

#[derive(Debug, Arbitrary)]
struct FuzzCheckResult {
    name: String,
    code: Option<String>,
    status: FuzzCheckStatus,
    severity: FuzzCheckSeverity,
    message: String,
    repair_hints: Vec<String>,
}

impl From<FuzzCheckResult> for CheckResult {
    fn from(value: FuzzCheckResult) -> Self {
        Self {
            name: bounded_string(value.name),
            connector_id: None,
            code: value.code.map(bounded_string),
            status: value.status.into(),
            severity: value.severity.into(),
            message: bounded_string(value.message),
            repair_hints: value
                .repair_hints
                .into_iter()
                .take(8)
                .map(bounded_string)
                .collect(),
        }
    }
}

fn bounded_string(mut value: String) -> String {
    value.truncate(256);
    value
}

fn assert_json_round_trip<T>(value: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let Ok(json) = serde_json::to_vec(value) else {
        return;
    };
    let Ok(decoded) = serde_json::from_slice::<T>(&json) else {
        panic!("doctor wire-format JSON should decode after encoding");
    };
    let Ok(reencoded) = serde_json::to_vec(&decoded) else {
        panic!("doctor wire-format JSON should reencode after decoding");
    };
    let _: T = serde_json::from_slice(&reencoded)
        .expect("doctor wire-format JSON should decode after reencoding");
}

fn fuzz_structured(data: &[u8]) {
    let mut input = Unstructured::new(data);

    if let Ok(freshness) = FuzzFreshnessLevel::arbitrary(&mut input) {
        let checkpoint = CheckpointStatus {
            freshness: freshness.into(),
        };
        let revocation = RevocationStatus {
            freshness: freshness.into(),
        };
        let audit = AuditStatus {
            freshness: freshness.into(),
        };
        assert_json_round_trip(&checkpoint);
        assert_json_round_trip(&revocation);
        assert_json_round_trip(&audit);
    }

    if let Ok((allow_lan, allow_derp, allow_funnel)) = <(bool, bool, bool)>::arbitrary(&mut input) {
        let transport = TransportPolicyStatus {
            allow_lan,
            allow_derp,
            allow_funnel,
        };
        assert_json_round_trip(&transport);
    }

    if let Ok(store_healthy) = bool::arbitrary(&mut input) {
        let store = StoreCoverageStatus { store_healthy };
        assert_json_round_trip(&store);
    }

    if let Ok(is_degraded) = bool::arbitrary(&mut input) {
        let degraded = DegradedModeStatus { is_degraded };
        assert_json_round_trip(&degraded);
    }

    if let Ok(result) = FuzzCheckResult::arbitrary(&mut input) {
        assert_json_round_trip(&CheckResult::from(result));
    }
}

fn fuzz_json(data: &[u8]) {
    let Ok(json) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(value) = serde_json::from_str::<CheckpointStatus>(json) {
        assert_json_round_trip(&value);
    }
    if let Ok(value) = serde_json::from_str::<RevocationStatus>(json) {
        assert_json_round_trip(&value);
    }
    if let Ok(value) = serde_json::from_str::<AuditStatus>(json) {
        assert_json_round_trip(&value);
    }
    if let Ok(value) = serde_json::from_str::<TransportPolicyStatus>(json) {
        assert_json_round_trip(&value);
    }
    if let Ok(value) = serde_json::from_str::<StoreCoverageStatus>(json) {
        assert_json_round_trip(&value);
    }
    if let Ok(value) = serde_json::from_str::<DegradedModeStatus>(json) {
        assert_json_round_trip(&value);
    }
    if let Ok(value) = serde_json::from_str::<CheckResult>(json) {
        assert_json_round_trip(&value);
    }
}

fuzz_target!(|data: &[u8]| {
    fuzz_structured(data);
    fuzz_json(data);
});
