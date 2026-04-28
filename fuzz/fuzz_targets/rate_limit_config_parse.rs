#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{OperationRateLimitScope, RateLimit, RateLimitValidationError};
use libfuzzer_sys::fuzz_target;

const MAX_TEXT_BYTES: usize = 256;
const MAX_JSON_BYTES: usize = 4096;

#[derive(Arbitrary, Debug)]
struct Input {
    max: u32,
    per_ms: u64,
    burst: Option<u32>,
    scope: Option<Vec<u8>>,
    pool_name: Option<Vec<u8>>,
    raw_json: Vec<u8>,
}

fn bounded_lossy(bytes: &[u8], max: usize) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(max)]).into_owned()
}

fn scope_from_index(index: u8) -> Option<String> {
    match index % 6 {
        0 => None,
        1 => Some("per_connector".to_string()),
        2 => Some("per_zone".to_string()),
        3 => Some("per_principal".to_string()),
        4 => Some("PER_CONNECTOR".to_string()),
        _ => Some("per-project".to_string()),
    }
}

fn valid_pool_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

fn assert_rate_limit_contract(rate_limit: &RateLimit) {
    let validation = rate_limit.validate();
    let expected_error = if rate_limit.max == 0 {
        Some(RateLimitValidationError::ZeroMax)
    } else if rate_limit.per_ms == 0 {
        Some(RateLimitValidationError::ZeroPeriod)
    } else if let Some(scope) = &rate_limit.scope {
        if scope.parse::<OperationRateLimitScope>().is_err() {
            Some(RateLimitValidationError::InvalidScope {
                scope: scope.clone(),
            })
        } else if let Some(pool_name) = &rate_limit.pool_name {
            expected_pool_name_error(pool_name)
        } else {
            None
        }
    } else if let Some(pool_name) = &rate_limit.pool_name {
        expected_pool_name_error(pool_name)
    } else {
        None
    };

    assert_eq!(validation.err(), expected_error);

    let expected_scope = rate_limit
        .scope
        .as_deref()
        .and_then(|scope| scope.parse().ok())
        .unwrap_or_default();
    assert_eq!(rate_limit.parsed_scope(), expected_scope);
}

fn expected_pool_name_error(pool_name: &str) -> Option<RateLimitValidationError> {
    if pool_name.is_empty() {
        Some(RateLimitValidationError::EmptyPoolName)
    } else if !valid_pool_name(pool_name) {
        Some(RateLimitValidationError::InvalidPoolName {
            pool_name: pool_name.to_string(),
        })
    } else {
        None
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    let scope = input
        .scope
        .as_deref()
        .map(|bytes| bounded_lossy(bytes, MAX_TEXT_BYTES))
        .or_else(|| scope_from_index(input.max as u8));
    let pool_name = input
        .pool_name
        .as_deref()
        .map(|bytes| bounded_lossy(bytes, MAX_TEXT_BYTES));

    let rate_limit = RateLimit {
        max: input.max,
        per_ms: input.per_ms,
        burst: input.burst,
        scope,
        pool_name,
    };
    assert_rate_limit_contract(&rate_limit);

    let json = serde_json::to_string(&rate_limit).expect("RateLimit serializes");
    let reparsed: RateLimit = serde_json::from_str(&json).expect("serialized RateLimit parses");
    assert_eq!(reparsed.max, rate_limit.max);
    assert_eq!(reparsed.per_ms, rate_limit.per_ms);
    assert_eq!(reparsed.burst, rate_limit.burst);
    assert_eq!(reparsed.scope, rate_limit.scope);
    assert_eq!(reparsed.pool_name, rate_limit.pool_name);
    assert_rate_limit_contract(&reparsed);

    let raw_json = bounded_lossy(&input.raw_json, MAX_JSON_BYTES);
    if let Ok(parsed) = serde_json::from_str::<RateLimit>(&raw_json) {
        assert_rate_limit_contract(&parsed);
    }
});
