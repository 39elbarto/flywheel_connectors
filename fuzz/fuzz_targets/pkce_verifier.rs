#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_oauth::{Pkce, PkceMethod};
use libfuzzer_sys::fuzz_target;

const MAX_VERIFIER_LEN: usize = 4 * 1024;

#[derive(Arbitrary, Debug)]
enum FuzzMethod {
    Plain,
    S256,
}

impl From<FuzzMethod> for PkceMethod {
    fn from(m: FuzzMethod) -> Self {
        match m {
            FuzzMethod::Plain => PkceMethod::Plain,
            FuzzMethod::S256 => PkceMethod::S256,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct PkceInput<'a> {
    verifier: &'a str,
    method: FuzzMethod,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = PkceInput::arbitrary(&mut u) else {
        return;
    };

    if input.verifier.len() > MAX_VERIFIER_LEN {
        return;
    }

    let method: PkceMethod = input.method.into();

    match Pkce::from_verifier(input.verifier, method) {
        Ok(pkce) => {
            // RFC 7636 §4.1: accepted verifier length must be 43..=128.
            assert!(
                pkce.verifier().len() >= 43 && pkce.verifier().len() <= 128,
                "from_verifier accepted out-of-range length {}",
                pkce.verifier().len()
            );
            // All accepted characters must be [A-Za-z0-9-._~].
            assert!(
                pkce.verifier().chars().all(|c| {
                    c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~'
                }),
                "from_verifier accepted invalid characters"
            );
            // Challenge must be non-empty for any accepted verifier.
            assert!(!pkce.challenge().is_empty());
            assert_eq!(pkce.method(), method);
        }
        Err(_) => {
            // Expected for invalid inputs — no assertions.
        }
    }
});
