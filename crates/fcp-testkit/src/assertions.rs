//! Assertion helpers for FCP testing.
//!
//! Provides convenient assertion macros and functions for common test patterns.

use fcp_core::{FcpError, FcpResult, HealthSnapshot, HealthState, InvokeResponse};

// ─────────────────────────────────────────────────────────────────────────────
// Result Assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that a result is successful.
///
/// # Panics
///
/// Panics if the result is an error.
pub fn assert_ok<T: std::fmt::Debug>(result: &FcpResult<T>) {
    assert!(result.is_ok(), "Expected Ok but got: {result:?}");
}

/// Assert that a result is an error.
///
/// # Panics
///
/// Panics if the result is Ok.
pub fn assert_err<T: std::fmt::Debug>(result: &FcpResult<T>) {
    assert!(result.is_err(), "Expected Err but got: {result:?}");
}

/// Assert that a result is a specific error type.
///
/// # Panics
///
/// Panics if the result is Ok or a different error type.
pub fn assert_error_type<T: std::fmt::Debug>(result: &FcpResult<T>, expected: &str) {
    match result {
        Ok(v) => panic!("Expected error '{expected}' but got Ok({v:?})"),
        Err(e) => {
            let error_str = format!("{e:?}");
            assert!(
                error_str.contains(expected),
                "Expected error containing '{expected}' but got: {error_str}",
            );
        }
    }
}

/// Assert that a result is a `NotConfigured` error.
///
/// # Panics
///
/// Panics if the result is not a `NotConfigured` error.
pub fn assert_not_configured<T: std::fmt::Debug>(result: &FcpResult<T>) {
    match result {
        Err(FcpError::NotConfigured) => {}
        other => panic!("Expected NotConfigured error but got: {other:?}"),
    }
}

/// Assert that a result is a `NotHandshaken` error.
///
/// # Panics
///
/// Panics if the result is not a `NotHandshaken` error.
pub fn assert_not_handshaken<T: std::fmt::Debug>(result: &FcpResult<T>) {
    match result {
        Err(FcpError::NotHandshaken) => {}
        other => panic!("Expected NotHandshaken error but got: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that a health snapshot indicates ready status.
///
/// # Panics
///
/// Panics if the status is not Ready.
pub fn assert_healthy(snapshot: &HealthSnapshot) {
    let status = &snapshot.status;
    assert!(
        snapshot.is_ready(),
        "Expected Ready status but got: {status:?}"
    );
}

/// Assert that a health snapshot indicates degraded status.
///
/// # Panics
///
/// Panics if the status is not Degraded.
pub fn assert_degraded(snapshot: &HealthSnapshot) {
    let status = &snapshot.status;
    assert!(
        matches!(snapshot.status, HealthState::Degraded { .. }),
        "Expected Degraded status but got: {status:?}",
    );
}

/// Assert that a health snapshot indicates error status.
///
/// # Panics
///
/// Panics if the status is not Error.
pub fn assert_unhealthy(snapshot: &HealthSnapshot) {
    let status = &snapshot.status;
    assert!(
        matches!(snapshot.status, HealthState::Error { .. }),
        "Expected Error status but got: {status:?}",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// InvokeResponse Assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that an invoke response has a non-null result.
///
/// # Panics
///
/// Panics if result is null or None.
pub fn assert_has_result(response: &InvokeResponse) {
    if let Some(val) = &response.result {
        assert!(!val.is_null(), "Expected result but got JSON null");
    } else {
        panic!("Expected result but got None");
    }
}

/// Assert that an invoke response has a null result.
///
/// # Panics
///
/// Panics if result is not null/None.
pub fn assert_no_result(response: &InvokeResponse) {
    if let Some(val) = &response.result {
        assert!(val.is_null(), "Expected null result but got: {val:?}");
    }
}

/// Assert that an invoke response result contains a specific field.
///
/// # Panics
///
/// Panics if the field is missing.
pub fn assert_result_has_field(response: &InvokeResponse, field: &str) {
    let result = response.result.as_ref().expect("Response has no result");
    assert!(
        result.get(field).is_some(),
        "Expected field '{field}' in result but got: {result:?}"
    );
}

/// Assert that an invoke response result field equals a specific value.
///
/// # Panics
///
/// Panics if the field doesn't match.
pub fn assert_result_field_eq(
    response: &InvokeResponse,
    field: &str,
    expected: &serde_json::Value,
) {
    let result = response.result.as_ref().expect("Response has no result");
    let actual = result.get(field).unwrap_or(&serde_json::Value::Null);
    assert_eq!(
        actual, expected,
        "Expected field '{field}' to equal {expected:?} but got {actual:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON Assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that a JSON value contains a field.
///
/// # Panics
///
/// Panics if the field is missing.
pub fn assert_json_has(value: &serde_json::Value, path: &str) {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = value;

    for part in &parts {
        match current.get(*part) {
            Some(v) => current = v,
            None => panic!("Missing field '{part}' in path '{path}'. JSON: {value:?}"),
        }
    }
}

/// Assert that a JSON value equals an expected value.
///
/// # Panics
///
/// Panics if values don't match.
pub fn assert_json_eq(actual: &serde_json::Value, expected: &serde_json::Value) {
    assert_eq!(
        actual,
        expected,
        "JSON values don't match.\nExpected: {}\nActual: {}",
        serde_json::to_string_pretty(expected).unwrap_or_default(),
        serde_json::to_string_pretty(actual).unwrap_or_default()
    );
}

/// Assert that a JSON array has a specific length.
///
/// # Panics
///
/// Panics if length doesn't match or value isn't an array.
pub fn assert_json_array_len(value: &serde_json::Value, expected_len: usize) {
    let array = value.as_array().expect("Expected JSON array");
    assert_eq!(
        array.len(),
        expected_len,
        "Expected array of length {expected_len} but got {}",
        array.len()
    );
}

/// Assert that a JSON value is a string matching a pattern.
///
/// # Panics
///
/// Panics if value isn't a string or doesn't match pattern.
pub fn assert_json_string_contains(value: &serde_json::Value, pattern: &str) {
    let s = value.as_str().expect("Expected JSON string");
    assert!(
        s.contains(pattern),
        "Expected string containing '{pattern}' but got '{s}'"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Timing Assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that an async operation completes within a timeout.
///
/// # Panics
///
/// Panics if the operation times out.
pub async fn assert_completes_within<F, T>(future: F, timeout: std::time::Duration) -> T
where
    F: std::future::Future<Output = T>,
{
    fcp_async_core::time::timeout(timeout, future)
        .await
        .expect("Operation timed out")
}

/// Assert that an async operation takes at least a minimum duration.
///
/// # Panics
///
/// Panics if the operation completes too quickly.
pub async fn assert_takes_at_least<F, T>(future: F, min_duration: std::time::Duration) -> T
where
    F: std::future::Future<Output = T>,
{
    let start = std::time::Instant::now();
    let result = future.await;
    let elapsed = start.elapsed();

    assert!(
        elapsed >= min_duration,
        "Expected operation to take at least {min_duration:?} but completed in {elapsed:?}"
    );

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assert_json_has() {
        let json = serde_json::json!({
            "user": {
                "name": "test",
                "email": "test@example.com"
            }
        });

        assert_json_has(&json, "user");
        assert_json_has(&json, "user.name");
        assert_json_has(&json, "user.email");
    }

    #[test]
    #[should_panic(expected = "Missing field")]
    fn test_assert_json_has_missing() {
        let json = serde_json::json!({"user": {}});
        assert_json_has(&json, "user.name");
    }

    #[test]
    fn test_assert_json_array_len() {
        let json = serde_json::json!([1, 2, 3]);
        assert_json_array_len(&json, 3);
    }
}
