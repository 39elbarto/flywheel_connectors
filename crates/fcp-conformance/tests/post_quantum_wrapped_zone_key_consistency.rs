//! Post-quantum conformance: V3 and promoted V4 zone-key wraps resolve identically.

use fcp_core::{
    TailscaleNodeId, WrappedKey, WrappedZoneKey, ZONE_KEY_LEN, ZoneId, ZoneKemAlgorithm, ZoneKey,
    unwrap_zone_key, wrap_zone_key,
};
use fcp_crypto::X25519SecretKey;

#[test]
fn promoted_wrapped_zone_key_v4_derives_same_effective_zone_key_bytes() {
    let zone_id = ZoneId::work();
    let recipient = TailscaleNodeId::new("recipient-promoted-v4");
    let issued_at = 1_700_000_333;
    let recipient_secret = X25519SecretKey::from_bytes([0x44; 32]);
    let zone_key = ZoneKey::from_bytes([0x77; ZONE_KEY_LEN]);

    let v3_wrap = wrap_zone_key(
        &recipient_secret.public_key(),
        &zone_id,
        &recipient,
        issued_at,
        &zone_key,
    )
    .expect("V3 HPKE wrap succeeds");
    let promoted_v4 = v3_wrap.to_v4();
    assert_eq!(promoted_v4.sealed.kem(), ZoneKemAlgorithm::HpkeX25519);

    let WrappedKey::HpkeX25519 { sealed } = promoted_v4.sealed.clone() else {
        panic!("promoted V4 wrap must retain HPKE sealed box");
    };
    let v4_as_legacy = WrappedZoneKey {
        recipient,
        issued_at,
        sealed,
    };

    let opened_v3 = unwrap_zone_key(&recipient_secret, &zone_id, &v3_wrap).expect("V3 wrap opens");
    let opened_v4 =
        unwrap_zone_key(&recipient_secret, &zone_id, &v4_as_legacy).expect("V4 wrap opens");

    assert_eq!(opened_v3.as_bytes(), zone_key.as_bytes());
    assert_eq!(opened_v4.as_bytes(), zone_key.as_bytes());
    assert_eq!(
        opened_v3.as_bytes(),
        opened_v4.as_bytes(),
        "WrappedZoneKey and promoted WrappedZoneKeyV4 must derive identical effective key bytes"
    );
}
