//! Provenance Record Fuzz Target.
//!
//! ProvenanceRecord is deserialized from CBOR bytes that travel inside
//! ObjectHeader across the FCPS/FCPC wire. An attacker controls every
//! field: zone ids, integrity/confidentiality labels, taint flags, and
//! the three history vectors (label_adjustments, taint_reductions,
//! zone_crossings). After deserialization the record is consumed by
//! security-critical policy decisions — `can_flow_to`, `can_drive_operation`,
//! and `merge` across multiple input records.
//!
//! Goal: ensure no adversarial CBOR input can panic any of those routines,
//! and that canonical re-encoding is stable (decode → encode → decode
//! must converge on identical bytes).

#![no_main]

use fcp_cbor::{SchemaId, to_canonical_cbor};
use fcp_core::{
    ConfidentialityLevel, IntegrityLevel, ProvenanceRecord, SafetyTier, TaintFlag, ZoneId,
};
use libfuzzer_sys::fuzz_target;
use semver::Version;

const MAX_INPUT_BYTES: usize = 32 * 1024;

fn safe_zones() -> Vec<ZoneId> {
    vec![
        ZoneId::owner(),
        ZoneId::private(),
        ZoneId::work(),
        ZoneId::community(),
        ZoneId::public(),
    ]
}

fn exercise_record(record: &ProvenanceRecord) {
    // Label accessors must never panic even if the deserialized labels
    // point outside the canonical lattice — they read a discriminant.
    let _ = record.integrity_label;
    let _ = record.confidentiality_label;

    // Flow checks against every canonical target zone.
    for target in safe_zones() {
        let _ = record.can_flow_to(&target);
    }

    // Operation authorization for every SafetyTier.
    for tier in [
        SafetyTier::Safe,
        SafetyTier::Risky,
        SafetyTier::Dangerous,
        SafetyTier::Critical,
        SafetyTier::Forbidden,
    ] {
        let _ = record.can_drive_operation(tier);
    }

    // Inspect taint flags (iter + critical check must not panic).
    let _ = record.taint_flags.has_critical();
    let _: usize = record.taint_flags.iter().count();
    for flag in [
        TaintFlag::PublicInput,
        TaintFlag::PotentiallyMalicious,
        TaintFlag::CrossZoneUnapproved,
    ] {
        let _ = record.taint_flags.contains(flag);
    }

    // Zone-level derivations used by merge and flow checks.
    let _ = IntegrityLevel::from_zone(&record.current_zone);
    let _ = ConfidentialityLevel::from_zone(&record.origin_zone);

    // Merge with a fresh record — exercises the MIN/MAX/OR fold paths
    // that reach every label and taint-flag field of the attacker input.
    let mut others = Vec::new();
    for target in safe_zones() {
        let fresh = ProvenanceRecord::new(target.clone());
        others.push(fresh);
    }
    let refs: Vec<&ProvenanceRecord> = std::iter::once(record).chain(others.iter()).collect();
    let _merged = ProvenanceRecord::merge(&refs, ZoneId::work());
}

fn roundtrip_canonical(record: &ProvenanceRecord) {
    // If the record serializes, round-tripping through canonical CBOR
    // must give a byte-stable encoding.
    if let Ok(canonical) = to_canonical_cbor(record)
        && let Ok(decoded) = ciborium::from_reader::<ProvenanceRecord, _>(&canonical[..])
        && let Ok(recanonical) = to_canonical_cbor(&decoded)
    {
        assert_eq!(canonical, recanonical, "canonical CBOR not stable");
        // Also exercise the roundtripped value — ensures the decoded shape
        // is still policy-evaluable, not just structurally valid CBOR.
        exercise_record(&decoded);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    // Treat the fuzzer input as raw ciborium bytes for a ProvenanceRecord.
    if let Ok(record) = ciborium::from_reader::<ProvenanceRecord, _>(data) {
        exercise_record(&record);
        roundtrip_canonical(&record);
    }

    // Also try framing the input behind a SchemaId hash so we exercise
    // the CanonicalSerializer decode path the way the kernel does.
    if data.len() >= fcp_cbor::SCHEMA_HASH_LEN {
        let schema = SchemaId::new("fcp.core", "ProvenanceRecord", Version::new(1, 0, 0));
        let mut framed = Vec::with_capacity(fcp_cbor::SCHEMA_HASH_LEN + data.len());
        framed.extend_from_slice(schema.hash().as_bytes());
        framed.extend_from_slice(data);
        let _ = fcp_cbor::CanonicalSerializer::deserialize::<ProvenanceRecord>(&framed, &schema);
    }
});
