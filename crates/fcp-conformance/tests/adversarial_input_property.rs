use std::panic::{AssertUnwindSafe, catch_unwind};

use fcp_auth_schema::{AuthClaims, claims::CURRENT_SCHEMA_VERSION};
use fcp_crypto::cose::{CoseToken, CwtClaims};
use fcp_protocol::{FCPS_HEADER_LEN, FcpcFrame, FcpcFrameHeader, FcpsFrame, FcpsFrameHeader};
use proptest::prelude::*;
use proptest::test_runner::Config;

const CASES: u32 = 10_000;
const SECRET_CASES: u32 = 1_000;
const MAX_INPUT_LEN: usize = 16 * 1024;
const FCPS_FUZZ_MTU: usize = 65_536;
const SECRET_MARKER: &str = "fcp-secret-marker-do-not-leak";

fn bounded_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..MAX_INPUT_LEN)
}

fn assert_no_panic<F>(parse: F)
where
    F: FnOnce(),
{
    assert!(
        catch_unwind(AssertUnwindSafe(parse)).is_ok(),
        "parser panicked on adversarial bytes"
    );
}

fn parse_fcpc(data: &[u8]) -> Vec<String> {
    let mut errors = Vec::new();
    if let Err(error) = FcpcFrameHeader::decode(data) {
        errors.push(error.to_string());
    }
    if let Err(error) = FcpcFrame::decode(data) {
        errors.push(error.to_string());
    }
    for limit in [0, 64, 256, 1024, 4096, 65_536] {
        if let Err(error) = FcpcFrame::decode_with_limit(data, limit) {
            errors.push(error.to_string());
        }
    }
    errors
}

fn parse_fcps(data: &[u8]) -> Vec<String> {
    let mut errors = Vec::new();
    if let Err(error) = FcpsFrameHeader::decode(data) {
        errors.push(error.to_string());
    }
    for mtu in [0usize, 64, FCPS_HEADER_LEN, 4096, FCPS_FUZZ_MTU] {
        if let Err(error) = FcpsFrame::decode(data, mtu) {
            errors.push(error.to_string());
        }
    }
    errors
}

fn parse_cose(data: &[u8]) -> Vec<String> {
    let mut errors = Vec::new();
    match CoseToken::from_cbor(data) {
        Ok(token) => {
            if let Err(error) = token.to_cbor() {
                errors.push(error.to_string());
            }
            if let Err(error) = token.claims_unverified() {
                errors.push(error.to_string());
            }
        }
        Err(error) => errors.push(error.to_string()),
    }
    if let Err(error) = CwtClaims::from_cbor(data) {
        errors.push(error.to_string());
    }
    errors
}

fn parse_auth_claims(data: &[u8]) -> Vec<String> {
    match AuthClaims::from_canonical_cbor(data) {
        Ok(claims) => {
            let mut errors = Vec::new();
            if let Err(error) = claims.to_canonical_cbor() {
                errors.push(error.to_string());
            }
            if let Err(error) = claims.check_schema_version(&[CURRENT_SCHEMA_VERSION]) {
                errors.push(error.to_string());
            }
            errors
        }
        Err(error) => vec![error.to_string()],
    }
}

proptest! {
    #![proptest_config(Config::with_cases(CASES))]

    #[test]
    fn test_fcpc_frame_no_panic_on_random_bytes(data in bounded_bytes()) {
        assert_no_panic(|| {
            let _ = parse_fcpc(&data);
        });
    }

    #[test]
    fn test_fcps_frame_no_panic_on_random_bytes(data in bounded_bytes()) {
        assert_no_panic(|| {
            let _ = parse_fcps(&data);
        });
    }

    #[test]
    fn test_cose_envelope_no_panic_on_random_bytes(data in bounded_bytes()) {
        assert_no_panic(|| {
            let _ = parse_cose(&data);
        });
    }

    #[test]
    fn test_capability_claim_no_panic_on_random_bytes(data in bounded_bytes()) {
        assert_no_panic(|| {
            let _ = parse_auth_claims(&data);
        });
    }
}

proptest! {
    #![proptest_config(Config::with_cases(SECRET_CASES))]

    #[test]
    fn test_no_secret_leak_in_error_messages(mut suffix in bounded_bytes()) {
        let mut data = SECRET_MARKER.as_bytes().to_vec();
        data.append(&mut suffix);

        let errors = catch_unwind(AssertUnwindSafe(|| {
            let mut errors = Vec::new();
            errors.extend(parse_fcpc(&data));
            errors.extend(parse_fcps(&data));
            errors.extend(parse_cose(&data));
            errors.extend(parse_auth_claims(&data));
            errors
        }))
        .expect("parser panicked while checking secret-redaction errors");

        for error in errors {
            prop_assert!(
                !error.contains(SECRET_MARKER),
                "parser error leaked secret marker: {error}"
            );
        }
    }
}
