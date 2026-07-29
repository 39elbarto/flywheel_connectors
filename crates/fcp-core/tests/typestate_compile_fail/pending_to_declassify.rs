use fcp_core::{ApprovalToken, ConfidentialityLevel, ObjectId, Pending, ProvenanceRecord, ZoneId};

fn main() {
    let pending = ApprovalToken::<Pending>::new();
    let mut provenance = ProvenanceRecord::new(ZoneId::private());
    let object_id = ObjectId::from_unscoped_bytes(b"secret-object");

    let _ = fcp_core::declassify(
        &pending,
        &mut provenance,
        object_id,
        ConfidentialityLevel::Work,
        1_500,
    );
}
