use fcp_auth_schema::AuthClaims;
use fcp_crypto::cose::{CoseToken, MAX_COSE_TOKEN_BYTES};
use fcp_protocol::{
    FCPS_HEADER_LEN, FcpcFrame, FcpcFrameHeader, FcpsFrame, FcpsFrameHeader, SymbolRecord,
};
use proptest::prelude::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

const MAX_RANDOM_INPUT_BYTES: usize = 1024;
const FCPS_PROBE_MTU_BYTES: usize = 65536;
const SECRET_PREFIX: &[u8] = b"FCP_SECRET_DO_NOT_LEAK";
type ParserFn = fn(&[u8]) -> Result<(), String>;
type CorpusSpec = (&'static str, &'static str, ParserFn);

fn parse_fcpc_frame(data: &[u8]) -> Result<(), String> {
    let header_result = FcpcFrameHeader::decode(data);
    for max_payload_len in [0usize, 64, 256, 1024, 4096, 65536] {
        let _ = FcpcFrame::decode_with_limit(data, max_payload_len);
    }
    match FcpcFrame::decode(data) {
        Ok(frame) => {
            if frame.header.len as usize != frame.ciphertext.len() {
                return Err("decoded FCPC frame length fields diverged".into());
            }
            let encoded = frame.encode();
            let reparsed = FcpcFrame::decode(&encoded).map_err(|error| error.to_string())?;
            if reparsed != frame {
                return Err("FCPC decode/encode/decode roundtrip diverged".into());
            }
            Ok(())
        }
        Err(frame_error) => header_result
            .map(|_| ())
            .map_err(|header_error| format!("{header_error}; {frame_error}")),
    }
}

fn parse_fcps_frame(data: &[u8]) -> Result<(), String> {
    let header_result = FcpsFrameHeader::decode(data);
    for max_datagram_bytes in [0usize, 64, FCPS_HEADER_LEN, 4096, FCPS_PROBE_MTU_BYTES] {
        let _ = FcpsFrame::decode(data, max_datagram_bytes);
    }
    match FcpsFrame::decode(data, FCPS_PROBE_MTU_BYTES) {
        Ok(frame) => {
            let payload_len: usize = frame.symbols.iter().map(SymbolRecord::wire_size).sum();
            if payload_len != frame.header.total_payload_len as usize {
                return Err("decoded FCPS payload length diverged from header".into());
            }
            let encoded = frame.encode().map_err(|error| error.to_string())?;
            let reparsed = FcpsFrame::decode(&encoded, FCPS_PROBE_MTU_BYTES)
                .map_err(|error| error.to_string())?;
            if reparsed != frame {
                return Err("FCPS decode/encode/decode roundtrip diverged".into());
            }
            Ok(())
        }
        Err(frame_error) => header_result
            .map(|_| ())
            .map_err(|header_error| format!("{header_error}; {frame_error}")),
    }
}

fn parse_cose_envelope(data: &[u8]) -> Result<(), String> {
    if data.len() > MAX_COSE_TOKEN_BYTES {
        return Err("COSE input exceeds parser cap".into());
    }
    let token = CoseToken::from_cbor(data).map_err(|error| error.to_string())?;
    let encoded = token.to_cbor().map_err(|error| error.to_string())?;
    let reparsed = CoseToken::from_cbor(&encoded).map_err(|error| error.to_string())?;
    let _ = reparsed.claims_unverified();
    Ok(())
}

fn parse_capability_claims(data: &[u8]) -> Result<(), String> {
    let claims = AuthClaims::from_canonical_cbor(data).map_err(|error| error.to_string())?;
    let encoded = claims
        .to_canonical_cbor()
        .map_err(|error| error.to_string())?;
    let reparsed = AuthClaims::from_canonical_cbor(&encoded).map_err(|error| error.to_string())?;
    if reparsed != claims {
        return Err("capability claims canonical roundtrip diverged".into());
    }
    Ok(())
}

fn assert_no_panic(parser: fn(&[u8]) -> Result<(), String>, data: &[u8]) {
    let result = catch_unwind(AssertUnwindSafe(|| parser(data)));
    assert!(result.is_ok(), "parser panicked");
}

struct SecretTaintTracker {
    secret: &'static [u8],
    marker: &'static str,
}

impl SecretTaintTracker {
    const fn new(secret: &'static [u8], marker: &'static str) -> Self {
        Self { secret, marker }
    }

    fn input_with_secret(&self, suffix: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(self.secret.len() + suffix.len());
        input.extend_from_slice(self.secret);
        input.extend_from_slice(suffix);
        input
    }

    fn assert_redacted(&self, message: &str) {
        assert!(
            !message.contains(self.marker),
            "parser error leaked registered secret marker: {message}"
        );
    }
}

fn hex_corpus_lines(contents: &str) -> Vec<Vec<u8>> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| hex::decode(line).expect("seed corpus line must be valid hex"))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10000,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn test_fcpc_frame_no_panic_on_random_bytes(
        input in proptest::collection::vec(any::<u8>(), 0..=MAX_RANDOM_INPUT_BYTES)
    ) {
        let result = catch_unwind(AssertUnwindSafe(|| parse_fcpc_frame(&input)));
        prop_assert!(result.is_ok(), "FCPC parser panicked");
    }

    #[test]
    fn test_fcps_frame_no_panic_on_random_bytes(
        input in proptest::collection::vec(any::<u8>(), 0..=MAX_RANDOM_INPUT_BYTES)
    ) {
        let result = catch_unwind(AssertUnwindSafe(|| parse_fcps_frame(&input)));
        prop_assert!(result.is_ok(), "FCPS parser panicked");
    }

    #[test]
    fn test_cose_envelope_no_panic_on_random_bytes(
        input in proptest::collection::vec(any::<u8>(), 0..=MAX_RANDOM_INPUT_BYTES)
    ) {
        let result = catch_unwind(AssertUnwindSafe(|| parse_cose_envelope(&input)));
        prop_assert!(result.is_ok(), "COSE envelope parser panicked");
    }

    #[test]
    fn test_capability_claim_no_panic_on_random_bytes(
        input in proptest::collection::vec(any::<u8>(), 0..=MAX_RANDOM_INPUT_BYTES)
    ) {
        let result = catch_unwind(AssertUnwindSafe(|| parse_capability_claims(&input)));
        prop_assert!(result.is_ok(), "capability claim parser panicked");
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn test_no_secret_leak_in_error_messages(
        suffix in proptest::collection::vec(any::<u8>(), 0..=MAX_RANDOM_INPUT_BYTES)
    ) {
        let tracker = SecretTaintTracker::new(SECRET_PREFIX, "FCP_SECRET_DO_NOT_LEAK");
        let input = tracker.input_with_secret(&suffix);
        for parser in [
            parse_fcpc_frame,
            parse_fcps_frame,
            parse_cose_envelope,
            parse_capability_claims,
        ] {
            let result = catch_unwind(AssertUnwindSafe(|| parser(&input)));
            prop_assert!(result.is_ok(), "parser panicked while handling tainted input");
            if let Err(message) = result.expect("checked above") {
                tracker.assert_redacted(&message);
            }
        }
    }
}

#[test]
fn seed_corpora_have_at_least_ten_valid_samples_each() {
    let corpora: [CorpusSpec; 4] = [
        (
            "fcpc_frame_parser",
            include_str!("../../fcp-testkit/corpus/fcpc_frame_parser/seeds.hex"),
            parse_fcpc_frame,
        ),
        (
            "fcps_frame_parser",
            include_str!("../../fcp-testkit/corpus/fcps_frame_parser/seeds.hex"),
            parse_fcps_frame,
        ),
        (
            "cose_envelope_parser",
            include_str!("../../fcp-testkit/corpus/cose_envelope_parser/seeds.hex"),
            parse_cose_envelope,
        ),
        (
            "capability_claim_parser",
            include_str!("../../fcp-testkit/corpus/capability_claim_parser/seeds.hex"),
            parse_capability_claims,
        ),
    ];

    for (name, contents, parser) in corpora {
        let samples = hex_corpus_lines(contents);
        assert!(
            samples.len() >= 10,
            "{name} corpus must contain at least 10 seed samples"
        );
        for sample in samples {
            assert_no_panic(parser, &sample);
            assert!(
                parser(&sample).is_ok(),
                "{name} seed corpus sample must parse successfully"
            );
        }
    }
}
