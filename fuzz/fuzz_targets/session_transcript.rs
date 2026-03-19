#![no_main]

use fcp_crypto::X25519SecretKey;
use fcp_protocol::{
    MeshSessionId, SessionCryptoSuite, SessionDirection, SessionNonce, compute_session_mac,
    decode_ack_cbor, decode_cookie_bytes, decode_hello_cbor, derive_session_keys,
};
use fcp_core::TailscaleNodeId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        let _ = decode_cookie_bytes(data);
        return;
    }

    let mid = data.len() / 2;
    let (left, right) = data.split_at(mid);

    if let Ok(hello) = decode_hello_cbor(left) {
        let _ = hello.transcript_bytes();
        let _ = decode_cookie_bytes(left);

        if let Ok(ack) = decode_ack_cbor(right) {
            let _ = ack.transcript_bytes(&hello);
        }
    }

    if data.len() >= 64 {
        let mut sk_i = [0u8; 32];
        sk_i.copy_from_slice(&data[0..32]);
        let mut sk_r = [0u8; 32];
        sk_r.copy_from_slice(&data[32..64]);

        let initiator = TailscaleNodeId::new("node-initiator");
        let responder = TailscaleNodeId::new("node-responder");
        let session_id = MeshSessionId([0u8; 16]);
        let hello_nonce = SessionNonce([0u8; 16]);
        let ack_nonce = SessionNonce([1u8; 16]);

        let shared = match X25519SecretKey::from_bytes(sk_i).diffie_hellman(
            &X25519SecretKey::from_bytes(sk_r).public_key(),
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        if let Ok(keys) = derive_session_keys(
            &shared,
            &session_id,
            &initiator,
            &responder,
            &hello_nonce,
            &ack_nonce,
        ) {
            let _ = compute_session_mac(
                SessionCryptoSuite::Suite1,
                keys.mac_key(SessionDirection::InitiatorToResponder),
                &session_id,
                SessionDirection::InitiatorToResponder,
                1,
                right,
            );
        }
    }
});
