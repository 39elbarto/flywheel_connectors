//! COSE/CWT envelope parser fuzz target.

#![no_main]

use fcp_crypto::cose::{CoseToken, CwtClaims};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(token) = CoseToken::from_cbor(data) {
        let _ = token.to_cbor();
        let _ = token.claims_unverified();
        let _ = token.get_key_id();
    }
    if let Ok(claims) = CwtClaims::from_cbor(data) {
        let _ = claims.to_cbor();
    }
});
