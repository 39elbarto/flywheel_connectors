#![no_main]

use std::fmt::Debug;

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{ObjectId, TailscaleNodeId, ZoneId};
use fcp_mesh::{
    AcquireOutcome, HeldLease, LeaseCoordinator, LeaseCoordinatorConfig, LeasePurpose,
    ObservedLeaseAuthority, ReleaseOutcome, RenewOutcome,
};
use libfuzzer_sys::fuzz_target;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

const MAX_OBSERVED_LEASES: usize = 16;
const MAX_ELIGIBLE_NODES: usize = 8;
const NOW_BOUND_SECS: u64 = 10_000_000;

#[derive(Arbitrary, Debug)]
struct Input {
    subject: [u8; 32],
    alternate_subject: [u8; 32],
    requester: u8,
    purpose: u8,
    now_secs: u64,
    requested_ttl: u32,
    use_requested_ttl: bool,
    min_ttl_secs: u32,
    max_ttl_extra: u32,
    default_ttl_extra: u32,
    renew_threshold_bps: u16,
    max_leases_per_node: u8,
    escalate_dangerous_conflicts: bool,
    renew_token: u64,
    release_token: u64,
    eligible_nodes: Vec<u8>,
    observed_leases: Vec<LeaseInput>,
}

#[derive(Arbitrary, Debug)]
struct LeaseInput {
    holder: u8,
    use_alternate_subject: bool,
    purpose: u8,
    active: bool,
    expires_offset_secs: u16,
    fencing_token: u64,
}

fn purpose(discriminant: u8) -> LeasePurpose {
    match discriminant % 4 {
        0 => LeasePurpose::SingletonWriter,
        1 => LeasePurpose::OperationExecution,
        2 => LeasePurpose::CoordinatorElection,
        _ => LeasePurpose::Other,
    }
}

fn node(discriminant: u8) -> TailscaleNodeId {
    TailscaleNodeId::new(format!("node-{}", discriminant % 32))
}

fn config(input: &Input) -> LeaseCoordinatorConfig {
    let min_ttl_secs = (input.min_ttl_secs % 600).saturating_add(1);
    let max_ttl_secs = min_ttl_secs
        .saturating_add(input.max_ttl_extra % 3_600)
        .saturating_add(1);
    let default_ttl_secs =
        min_ttl_secs.saturating_add(input.default_ttl_extra % (max_ttl_secs - min_ttl_secs + 1));

    LeaseCoordinatorConfig {
        default_ttl_secs,
        min_ttl_secs,
        max_ttl_secs,
        renew_threshold_bps: input.renew_threshold_bps % 10_001,
        max_leases_per_node: usize::from((input.max_leases_per_node % 8).saturating_add(1)),
        escalate_dangerous_conflicts: input.escalate_dangerous_conflicts,
    }
}

fn observed(input: &Input, now_secs: u64, subject: ObjectId) -> Vec<ObservedLeaseAuthority> {
    input
        .observed_leases
        .iter()
        .take(MAX_OBSERVED_LEASES)
        .map(|lease| {
            let lease_subject = if lease.use_alternate_subject {
                ObjectId::from_bytes(input.alternate_subject)
            } else {
                subject
            };
            let offset = u64::from(lease.expires_offset_secs).saturating_add(1);
            let expires_at = if lease.active {
                now_secs.saturating_add(offset)
            } else {
                now_secs.saturating_sub(offset)
            };
            ObservedLeaseAuthority::new(
                node(lease.holder),
                HeldLease {
                    subject_id: lease_subject,
                    purpose: purpose(lease.purpose),
                    expires_at,
                    fencing_token: lease.fencing_token,
                },
            )
        })
        .collect()
}

fn eligible_nodes(input: &Input) -> Vec<TailscaleNodeId> {
    input
        .eligible_nodes
        .iter()
        .take(MAX_ELIGIBLE_NODES)
        .copied()
        .map(node)
        .collect()
}

fn json_outcome(value: &Value) -> &str {
    value
        .get("outcome")
        .and_then(Value::as_str)
        .expect("outcome wire shape must be internally tagged")
}

fn assert_wire_roundtrip<T>(value: &T, expected_outcome: &str)
where
    T: Serialize + DeserializeOwned + Eq + Debug,
{
    let json_bytes = serde_json::to_vec(value).expect("outcome must serialize to JSON");
    let json_decoded: T =
        serde_json::from_slice(&json_bytes).expect("outcome must deserialize from JSON");
    assert_eq!(&json_decoded, value, "JSON outcome roundtrip drifted");

    let json_value = serde_json::to_value(value).expect("outcome must serialize to JSON value");
    assert_eq!(
        json_outcome(&json_value),
        expected_outcome,
        "JSON outcome tag drifted"
    );

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(value, &mut cbor).expect("outcome must serialize to CBOR");
    let cbor_decoded: T =
        ciborium::de::from_reader(cbor.as_slice()).expect("outcome must deserialize from CBOR");
    assert_eq!(&cbor_decoded, value, "CBOR outcome roundtrip drifted");
}

fn assert_plain_roundtrip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + Eq + Debug,
{
    let json_bytes = serde_json::to_vec(value).expect("value must serialize to JSON");
    let json_decoded: T =
        serde_json::from_slice(&json_bytes).expect("value must deserialize from JSON");
    assert_eq!(&json_decoded, value, "JSON roundtrip drifted");

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(value, &mut cbor).expect("value must serialize to CBOR");
    let cbor_decoded: T =
        ciborium::de::from_reader(cbor.as_slice()).expect("value must deserialize from CBOR");
    assert_eq!(&cbor_decoded, value, "CBOR roundtrip drifted");
}

fn acquire_tag(outcome: &AcquireOutcome) -> &'static str {
    match outcome {
        AcquireOutcome::Granted { .. } => "granted",
        AcquireOutcome::Rejected { .. } => "rejected",
        AcquireOutcome::Denied { .. } => "denied",
        AcquireOutcome::Conflict { .. } => "conflict",
        _ => "unknown",
    }
}

fn renew_tag(outcome: &RenewOutcome) -> &'static str {
    match outcome {
        RenewOutcome::Renewed { .. } => "renewed",
        RenewOutcome::Denied { .. } => "denied",
        _ => "unknown",
    }
}

fn release_tag(outcome: &ReleaseOutcome) -> &'static str {
    match outcome {
        ReleaseOutcome::Released => "released",
        ReleaseOutcome::NotHeld { .. } => "not_held",
        _ => "unknown",
    }
}

fn assert_default_config_contract() {
    let defaults = LeaseCoordinatorConfig::default();
    assert_eq!(defaults.default_ttl_secs, 300);
    assert_eq!(defaults.min_ttl_secs, 10);
    assert_eq!(defaults.max_ttl_secs, 3_600);
    assert_eq!(defaults.renew_threshold_bps, 2_000);
    assert_eq!(defaults.max_leases_per_node, 64);
    assert!(defaults.escalate_dangerous_conflicts);
    assert!(defaults.min_ttl_secs <= defaults.default_ttl_secs);
    assert!(defaults.default_ttl_secs <= defaults.max_ttl_secs);
}

fuzz_target!(|data: &[u8]| {
    assert_default_config_contract();

    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    let now_secs = input.now_secs % NOW_BOUND_SECS;
    let subject = ObjectId::from_bytes(input.subject);
    let purpose = purpose(input.purpose);
    let requester = node(input.requester);
    let existing_leases = observed(&input, now_secs, subject);
    let eligible_nodes = eligible_nodes(&input);
    let config = config(&input);
    assert!(config.min_ttl_secs <= config.default_ttl_secs);
    assert!(config.default_ttl_secs <= config.max_ttl_secs);
    assert!(config.renew_threshold_bps <= 10_000);
    assert!(config.max_leases_per_node > 0);

    assert_plain_roundtrip(&config);

    let requested_ttl = input
        .use_requested_ttl
        .then_some(input.requested_ttl % config.max_ttl_secs.saturating_mul(2).max(1));
    let mut coordinator = LeaseCoordinator::new(config);

    let (acquire, acquire_events) = coordinator.acquire(
        &requester,
        &ZoneId::work(),
        &subject,
        &purpose,
        &existing_leases,
        &eligible_nodes,
        now_secs,
        requested_ttl,
    );
    assert_wire_roundtrip(&acquire, acquire_tag(&acquire));
    assert!(
        !acquire_events.is_empty(),
        "acquire should emit an authority timeline event"
    );

    let (renew, renew_events) = coordinator.renew(
        &requester,
        &subject,
        &purpose,
        input.renew_token,
        &existing_leases,
        now_secs,
        requested_ttl,
    );
    assert_wire_roundtrip(&renew, renew_tag(&renew));
    assert!(
        !renew_events.is_empty(),
        "renew should emit an authority timeline event"
    );

    let (release, release_events) = coordinator.release(
        &requester,
        &subject,
        &purpose,
        input.release_token,
        &existing_leases,
        now_secs,
    );
    assert_wire_roundtrip(&release, release_tag(&release));
    assert!(
        !release_events.is_empty(),
        "release should emit an authority timeline event"
    );
});
