use fcp_cbor::SchemaId;
use fcp_core::{
    Lease, LeaseParams, LeasePurpose, ObjectId, Provenance, SignatureSet, TailscaleNodeId, ZoneId,
    current_timestamp,
};
use semver::Version;

fn subject(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn lease_with_ttl(ttl_secs: u32) -> Lease {
    let zone_id = ZoneId::work();
    Lease::new(LeaseParams {
        schema: SchemaId::new("fcp.lease", "lease", Version::new(1, 0, 0)),
        zone_id: zone_id.clone(),
        holder: TailscaleNodeId::new("lease-expiry-holder"),
        lease_seq: 42,
        ttl_secs,
        subject_object_id: subject("lease-expiry-subject"),
        provenance: Provenance::new(zone_id),
        purpose: LeasePurpose::OperationExecution,
        quorum_signatures: SignatureSet::default(),
    })
}

#[test]
fn lease_new_sets_expiry_to_created_at_plus_ttl() {
    let before_create = current_timestamp();
    let ttl_secs = 300;

    let lease = lease_with_ttl(ttl_secs);

    let after_create = current_timestamp();
    assert!(
        (before_create..=after_create).contains(&lease.header.created_at),
        "created_at should be captured during Lease::new"
    );
    assert_eq!(lease.header.ttl_secs, Some(u64::from(ttl_secs)));
    assert_eq!(lease.exp, lease.header.created_at + u64::from(ttl_secs));
}

#[test]
fn lease_expiry_timestamps_compare_by_expiry_instant() {
    let short_lease = lease_with_ttl(30);
    let long_lease = lease_with_ttl(3_600);

    assert!(short_lease.exp < long_lease.exp);
    assert!(short_lease.exp.cmp(&long_lease.exp).is_lt());
    assert!(long_lease.exp.cmp(&short_lease.exp).is_gt());
}

#[test]
fn lease_is_fresh_before_expiry_and_expired_at_boundary() {
    let lease = lease_with_ttl(600);

    assert!(!lease.is_expired(lease.exp - 1));
    assert!(lease.is_expired(lease.exp));
    assert!(lease.is_expired(lease.exp + 1));
}
