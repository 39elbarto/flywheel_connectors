#![no_main]

use fcp_auth_schema::AuthClaims;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(claims) = AuthClaims::from_canonical_cbor(data) {
        let canonical = claims
            .to_canonical_cbor()
            .expect("decoded auth claims must re-encode");
        assert_eq!(data, canonical.as_slice());

        let reparsed =
            AuthClaims::from_canonical_cbor(&canonical).expect("canonical auth claims must parse");
        assert_eq!(claims, reparsed);
    }
});
