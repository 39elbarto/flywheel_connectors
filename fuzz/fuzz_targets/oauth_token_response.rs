#![no_main]

use fcp_oauth::{OAuthTokens, TokenResponse};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(response) = serde_json::from_slice::<TokenResponse>(data) else {
        return;
    };

    let validated = response.clone().validate();
    let Ok(validated) = validated else { return };

    let Ok(mut tokens) = OAuthTokens::from_response(validated.clone()) else {
        return;
    };

    // Spec invariants that must hold on every accepted response.
    assert!(!tokens.access_token().is_empty());
    assert!(!tokens.token_type().is_empty());
    if let Some(refresh) = tokens.refresh_token() {
        assert!(!refresh.is_empty());
    }
    if let Some(id) = tokens.id_token() {
        assert!(!id.is_empty());
    }

    // Authorization header construction must not panic for an accepted response.
    let _ = tokens.authorization_header();

    // Exercise the mutation path — scope-widening and empty-token guards both live here.
    let _ = tokens.update_from_response(validated);
});
