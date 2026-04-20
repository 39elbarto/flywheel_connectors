#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_oauth::{
    ensure_allowlisted_redirect_uri, ensure_callback_redirect_is_allowlisted,
    normalize_callback_redirect_uri, normalize_registered_redirect_uri,
    parse_registered_redirect_allowlist,
};
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

const MAX_ALLOWLIST_ENTRIES: usize = 8;
const MAX_URI_LEN: usize = 512;

#[derive(Arbitrary, Debug, Deserialize)]
struct RedirectAllowlistInput {
    allowlist: Vec<String>,
    redirect_uri: Option<String>,
    callback_url: Option<String>,
}

fn clamp_string(raw: &str) -> String {
    raw.chars().take(MAX_URI_LEN).collect()
}

fuzz_target!(|data: &[u8]| {
    let input = if let Ok(seed) = serde_json::from_slice::<RedirectAllowlistInput>(data) {
        seed
    } else {
        let mut unstructured = Unstructured::new(data);
        let Ok(seed) = RedirectAllowlistInput::arbitrary(&mut unstructured) else {
            return;
        };
        seed
    };

    let allowlist_owned: Vec<String> = input
        .allowlist
        .iter()
        .take(MAX_ALLOWLIST_ENTRIES)
        .map(|entry| clamp_string(entry))
        .collect();
    let allowlist_refs: Vec<&str> = allowlist_owned.iter().map(String::as_str).collect();

    let redirect_uri = input.redirect_uri.as_deref().map(clamp_string);
    let callback_url = input.callback_url.as_deref().map(clamp_string);

    if let Some(uri) = redirect_uri.as_deref() {
        let _ = normalize_registered_redirect_uri(uri, "redirect_uri");
    }
    if let Some(uri) = callback_url.as_deref() {
        let _ = normalize_callback_redirect_uri(uri);
    }

    if let Ok(allowlist) = parse_registered_redirect_allowlist(&allowlist_refs) {
        if let Some(uri) = redirect_uri.as_deref() {
            let result = ensure_allowlisted_redirect_uri(uri, &allowlist);
            if let Ok(normalized) = normalize_registered_redirect_uri(uri, "redirect_uri")
                && allowlist.contains(&normalized)
            {
                assert!(result.is_ok());
            }
        }

        if let Some(uri) = callback_url.as_deref() {
            let result = ensure_callback_redirect_is_allowlisted(uri, &allowlist);
            if let Ok(normalized) = normalize_callback_redirect_uri(uri)
                && allowlist.contains(&normalized)
            {
                assert!(result.is_ok());
            }
        }
    }
});
