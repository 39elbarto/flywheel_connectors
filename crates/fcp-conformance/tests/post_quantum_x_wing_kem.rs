//! Post-quantum conformance: X-Wing KEM round-trip across the compatibility ledger matrix.
//!
//! The compatibility ledger currently has one schema version and two protocol
//! versions. This harness pins the cross-product that matters during migration:
//! V3-only, V4-only, and dual V3/V4 entries all use the same X-Wing
//! encap/decap contract when V4 KEM material is present.

use std::collections::BTreeSet;

use fcp_crypto::{
    AeadKey, ChaCha20Nonce, ChaCha20Poly1305Cipher, Fcp4Aad, XWING_AEAD_INFO, XWingKem,
    XWingProvider, XWingSealedBox, XWingSecretKey,
};
use fcp_evidence::{
    COMPATIBILITY_LEDGER_VERSION, CompatibilityLedgerBody, EntryEvidence, EntryState, KemSuite,
    MeshCompatibilityLedger, MigrationPhase, NodeCompatibilityEntry, NodeFallbackPolicy,
    ProtocolVersion, SignatureSuite,
};
use serde::Deserialize;

const PLAINTEXT_ZONE_KEY: [u8; 32] = [0x5A; 32];
const EXPECTED_ZONE_KEY_HASH: &str =
    "4f56ba952f3e404b05e66f4c353e87159f912df32b131fc0c297d52ceb7fb5ee";

#[derive(Debug, Deserialize)]
struct XWingKat {
    #[serde(with = "hex::serde")]
    sk: Vec<u8>,
    #[serde(with = "hex::serde")]
    ct: Vec<u8>,
    #[serde(with = "hex::serde")]
    ss: Vec<u8>,
}

struct LedgerKemCase {
    name: &'static str,
    phase: MigrationPhase,
    protocols: &'static [ProtocolVersion],
    kems: &'static [KemSuite],
}

const LEDGER_KEM_CASES: &[LedgerKemCase] = &[
    LedgerKemCase {
        name: "v3-only-ledger-entry",
        phase: MigrationPhase::Observe,
        protocols: &[ProtocolVersion::V3],
        kems: &[KemSuite::HpkeX25519V3],
    },
    LedgerKemCase {
        name: "dual-v3-v4-ledger-entry",
        phase: MigrationPhase::DualAdvertise,
        protocols: &[ProtocolVersion::V3, ProtocolVersion::V4],
        kems: &[KemSuite::HpkeX25519V3, KemSuite::XWingMlKem768X25519],
    },
    LedgerKemCase {
        name: "v4-only-ledger-entry",
        phase: MigrationPhase::V4Only,
        protocols: &[ProtocolVersion::V4],
        kems: &[KemSuite::XWingMlKem768X25519],
    },
];

fn first_xwing_kat() -> XWingKat {
    let raw = include_str!("../../fcp-crypto/tests/data/xwing_test_vectors.json");
    let mut vectors: Vec<XWingKat> = serde_json::from_str(raw).expect("X-Wing KAT JSON parses");
    assert_eq!(vectors.len(), 3, "draft-06 X-Wing KAT corpus shape drifted");
    vectors.remove(0)
}

fn deterministic_sealed_box(kat: &XWingKat, aad: &[u8]) -> XWingSealedBox {
    let ss: [u8; 32] = kat.ss.as_slice().try_into().expect("KAT ss is 32 bytes");
    let key = fcp_crypto::hkdf_sha256_array::<32>(Some(aad), &ss, XWING_AEAD_INFO)
        .expect("X-Wing AEAD HKDF succeeds");
    let cipher = ChaCha20Poly1305Cipher::new(&AeadKey::from_bytes(key));
    let ciphertext = cipher
        .encrypt(
            &ChaCha20Nonce::from_bytes([0u8; 12]),
            &PLAINTEXT_ZONE_KEY,
            aad,
        )
        .expect("deterministic AEAD seal succeeds");
    XWingSealedBox {
        enc: kat.ct.clone(),
        ciphertext,
    }
}

fn ledger_for(case: &LedgerKemCase, epoch: u64) -> MeshCompatibilityLedger {
    let mut body = CompatibilityLedgerBody::new(
        format!("mesh-pq-conformance-{}", case.name),
        epoch,
        case.phase,
    );
    body.entries.insert(
        case.name.to_owned(),
        NodeCompatibilityEntry {
            node_id: case.name.to_owned(),
            node_attestation_hash: [0xA1; 32],
            claim_epoch: epoch,
            claim_issued_at_ms: 1_700_000_000_000,
            claim_expires_at_ms: 1_700_086_400_000,
            supported_protocols: case.protocols.iter().copied().collect(),
            signature_suites: BTreeSet::from([SignatureSuite::Ed25519V3, SignatureSuite::MlDsa65]),
            kem_suites: case.kems.iter().copied().collect(),
            fallback_policy: NodeFallbackPolicy::SafeReadOnlyOnly,
            state: EntryState::Verified,
            evidence: EntryEvidence {
                claim_hash: [0xB2; 32],
                observed_by: vec!["post-quantum-conformance".to_owned()],
                note: Some(case.name.to_owned()),
            },
        },
    );
    MeshCompatibilityLedger::unsigned(body)
}

#[test]
fn x_wing_kem_round_trips_for_every_compatibility_ledger_protocol_case() {
    let provider = XWingProvider::new();
    let kat = first_xwing_kat();
    let secret = XWingSecretKey::from_bytes(&kat.sk).expect("KAT secret key wraps");

    for (index, case) in LEDGER_KEM_CASES.iter().enumerate() {
        let ledger = ledger_for(case, u64::try_from(index + 1).expect("small index"));
        assert_eq!(
            ledger.body.ledger_version, COMPATIBILITY_LEDGER_VERSION,
            "ledger schema version must stay pinned for {}",
            case.name
        );
        let ledger_root = ledger.ledger_root().expect("ledger root derives");
        let aad =
            Fcp4Aad::for_zone_key(ledger_root.as_bytes(), case.name.as_bytes(), ledger.epoch())
                .encode()
                .expect("FCP4 AAD encodes");
        let sealed = deterministic_sealed_box(&kat, &aad);

        let opened = provider
            .open(&secret, &sealed, &aad)
            .unwrap_or_else(|err| panic!("{} X-Wing decap/open failed: {err}", case.name));
        assert_eq!(
            opened, PLAINTEXT_ZONE_KEY,
            "{} must recover the same zone-key bytes",
            case.name
        );
        assert_eq!(
            blake3::hash(&opened).to_hex().as_str(),
            EXPECTED_ZONE_KEY_HASH,
            "{} opened zone-key golden hash drifted",
            case.name
        );
    }
}
