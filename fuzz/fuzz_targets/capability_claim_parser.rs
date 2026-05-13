//! Typed capability-claim parser fuzz target.

#![no_main]

use fcp_auth_schema::AuthClaims;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(claims) = AuthClaims::from_canonical_cbor(data) {
        let _ = claims.to_canonical_cbor();
        let _ = claims.check_schema_version(&[fcp_auth_schema::claims::CURRENT_SCHEMA_VERSION]);
    }
});
