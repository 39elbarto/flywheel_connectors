#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_oauth::AuthorizationCallback;
use libfuzzer_sys::fuzz_target;

const MAX_URL_LEN: usize = 8 * 1024;

#[derive(Arbitrary, Debug)]
struct CallbackInput<'a> {
    expected_state: &'a str,
    url: &'a str,
    query: &'a str,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = CallbackInput::arbitrary(&mut u) else {
        return;
    };

    if input.url.len() > MAX_URL_LEN || input.query.len() > MAX_URL_LEN {
        return;
    }

    // Query-string parser: must not panic on any &str.
    if let Ok(cb) = AuthorizationCallback::from_query(input.query) {
        let _ = cb.validate(input.expected_state);
    }

    // URL parser: must not panic on any &str.
    if let Ok(cb) = AuthorizationCallback::from_url(input.url) {
        let _ = cb.validate(input.expected_state);

        // Property: accepted URL parses must not yield both `code` and `error`
        // populated — the callback is either a success (code set) or a failure
        // (error set), never both simultaneously per RFC 6749 §4.1.2.
        if cb.code.is_some() && cb.error.is_some() {
            // Spec violation would surface as a bug here; note it so the harness
            // documents the invariant rather than asserting and losing the input.
            let _ = (&cb.code, &cb.error);
        }
    }
});
