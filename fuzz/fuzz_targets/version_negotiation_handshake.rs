#![no_main]

use std::fs;
use std::path::{Component, Path, PathBuf};

use fcp_protocol::{SessionCryptoSuite, decode_ack_cbor, decode_hello_cbor, negotiate_suite};
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

const MAX_INPUT_BYTES: usize = 32 * 1024;
const MAX_SUITE_IDS: usize = 32;

#[derive(Debug, Deserialize)]
struct HandshakeSeed {
    hello_vector: Option<String>,
    ack_vector: Option<String>,
    initiator_suite_ids: Option<Vec<u8>>,
    responder_suite_ids: Option<Vec<u8>>,
}

fn sessions_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors/sessions")
}

fn safe_vector_path(root: &Path, name: &str) -> Option<PathBuf> {
    let path = Path::new(name);
    if path.components().count() != 1 {
        return None;
    }
    match path.components().next()? {
        Component::Normal(_) => Some(root.join(path)),
        _ => None,
    }
}

fn load_vector(root: &Path, name: &str) -> Option<Vec<u8>> {
    let path = safe_vector_path(root, name)?;
    fs::read(path).ok()
}

fn suites_from_ids(ids: &[u8]) -> Vec<SessionCryptoSuite> {
    ids.iter()
        .copied()
        .take(MAX_SUITE_IDS)
        .filter_map(|id| SessionCryptoSuite::try_from_id(id).ok())
        .collect()
}

fn exercise_negotiation(
    initiator_suites: &[SessionCryptoSuite],
    responder_suites: &[SessionCryptoSuite],
) {
    let chosen_a = negotiate_suite(initiator_suites, responder_suites);
    let chosen_b = negotiate_suite(initiator_suites, responder_suites);
    assert_eq!(chosen_a, chosen_b);

    if let Some(chosen) = chosen_a {
        assert!(initiator_suites.contains(&chosen));
        assert!(responder_suites.contains(&chosen));
    } else {
        assert!(
            !initiator_suites
                .iter()
                .any(|suite| responder_suites.contains(suite))
        );
    }
}

fn exercise_handshake(hello_bytes: &[u8], ack_bytes: &[u8]) {
    let hello = decode_hello_cbor(hello_bytes).ok();
    let ack = decode_ack_cbor(ack_bytes).ok();

    if let Some(hello) = hello.as_ref() {
        let _ = hello.transcript_bytes();
        let _ = hello.nonce.as_bytes();
        let _ = hello.eph_pubkey.to_bytes();
        exercise_negotiation(&hello.suites, &hello.suites);
    }

    if let Some(ack) = ack.as_ref() {
        let _ = ack.session_id.as_bytes();
        let _ = ack.nonce.as_bytes();
        let _ = ack.eph_pubkey.to_bytes();
    }

    if let (Some(hello), Some(ack)) = (hello.as_ref(), ack.as_ref()) {
        let _ = ack.transcript_bytes(hello);
        let chosen = negotiate_suite(&hello.suites, &[ack.suite]);
        if hello.suites.contains(&ack.suite) {
            assert_eq!(chosen, Some(ack.suite));
        } else {
            assert!(chosen.is_none());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(seed) = serde_json::from_slice::<HandshakeSeed>(data) {
        let root = sessions_dir();

        let hello_bytes = seed
            .hello_vector
            .as_deref()
            .and_then(|name| load_vector(&root, name));
        let ack_bytes = seed
            .ack_vector
            .as_deref()
            .and_then(|name| load_vector(&root, name));

        if let Some(hello_bytes) = hello_bytes.as_deref() {
            let _ = decode_hello_cbor(hello_bytes);
        }
        if let Some(ack_bytes) = ack_bytes.as_deref() {
            let _ = decode_ack_cbor(ack_bytes);
        }
        if let (Some(hello_bytes), Some(ack_bytes)) = (hello_bytes.as_deref(), ack_bytes.as_deref())
        {
            exercise_handshake(hello_bytes, ack_bytes);
        }

        if let (Some(initiator), Some(responder)) = (
            seed.initiator_suite_ids.as_deref(),
            seed.responder_suite_ids.as_deref(),
        ) {
            let initiator = suites_from_ids(initiator);
            let responder = suites_from_ids(responder);
            exercise_negotiation(&initiator, &responder);
        }
        return;
    }

    let midpoint = data.len() / 2;
    let (hello_bytes, ack_bytes) = data.split_at(midpoint);
    exercise_handshake(hello_bytes, ack_bytes);

    let initiator = suites_from_ids(hello_bytes);
    let responder = suites_from_ids(ack_bytes);
    exercise_negotiation(&initiator, &responder);
});
