//! Assertion helpers for FCP testing.
//!
//! Provides convenient assertion macros and functions for common test patterns.

use fcp_sdk::{FcpError, FcpResult, HealthSnapshot, HealthState, InvokeResponse};

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
// Connector Contract Assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Expected operation shape in a connector introspection payload.
#[derive(Debug, Clone, Copy)]
pub struct OperationContract<'a> {
    /// Operation ID that must be advertised.
    pub id: &'a str,

    /// Capability ID the operation must require.
    pub capability: &'a str,

    /// Input object fields that must be both declared and required.
    pub required_input_fields: &'a [&'a str],

    /// Output object fields that must be declared.
    pub output_fields: &'a [&'a str],
}

/// Assert that an introspection JSON payload declares the expected operation contracts.
///
/// # Panics
///
/// Panics if `introspection` does not contain an operations array, if an
/// expected operation is missing, or if any operation contract field does not
/// match the advertised schema.
pub fn assert_operation_contracts(
    introspection: &serde_json::Value,
    expected: &[OperationContract<'_>],
) {
    let operations = introspection_operations(introspection);
    assert_unique_operation_ids(operations);

    for contract in expected {
        let operation = find_operation(operations, contract.id);
        assert_eq!(
            json_string_field(operation, "capability"),
            contract.capability,
            "{} capability mismatch",
            contract.id
        );
        assert_object_schema(
            operation
                .get("input_schema")
                .unwrap_or_else(|| panic!("{} missing input_schema", contract.id)),
            contract.required_input_fields,
            contract.required_input_fields,
            "input_schema",
            contract.id,
        );
        assert_object_schema(
            operation
                .get("output_schema")
                .unwrap_or_else(|| panic!("{} missing output_schema", contract.id)),
            &[],
            contract.output_fields,
            "output_schema",
            contract.id,
        );
    }
}

fn introspection_operations(introspection: &serde_json::Value) -> &[serde_json::Value] {
    introspection
        .get("operations")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("introspection missing operations array: {introspection:?}"))
}

fn assert_unique_operation_ids(operations: &[serde_json::Value]) {
    let mut ids = std::collections::BTreeSet::new();
    for operation in operations {
        let id = json_string_field(operation, "id");
        assert!(ids.insert(id), "duplicate operation id advertised: {id}");
    }
}

fn find_operation<'a>(operations: &'a [serde_json::Value], id: &str) -> &'a serde_json::Value {
    operations
        .iter()
        .find(|operation| operation.get("id").and_then(serde_json::Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("missing operation contract for {id}"))
}

fn assert_object_schema(
    schema: &serde_json::Value,
    required_fields: &[&str],
    declared_fields: &[&str],
    schema_name: &str,
    operation_id: &str,
) {
    assert_eq!(
        json_string_field(schema, "type"),
        "object",
        "{operation_id} {schema_name} must be an object schema"
    );

    let required = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let properties = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("{operation_id} {schema_name} missing properties object"));

    for field in required_fields {
        assert!(
            required
                .iter()
                .any(|candidate| candidate.as_str() == Some(*field)),
            "{operation_id} {schema_name} does not require field {field}"
        );
    }

    for field in declared_fields {
        assert!(
            properties.contains_key(*field),
            "{operation_id} {schema_name} does not declare property {field}"
        );
    }
}

fn json_string_field<'a>(value: &'a serde_json::Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {field}: {value:?}"))
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

    #[test]
    fn test_assert_json_array_len_empty() {
        let json = serde_json::json!([]);
        assert_json_array_len(&json, 0);
    }

    #[test]
    #[should_panic(expected = "Expected array of length")]
    fn test_assert_json_array_len_mismatch() {
        let json = serde_json::json!([1, 2]);
        assert_json_array_len(&json, 5);
    }

    // ---- assert_ok / assert_err ----

    #[test]
    fn test_assert_ok_passes() {
        let result: FcpResult<i32> = Ok(42);
        assert_ok(&result);
    }

    #[test]
    #[should_panic(expected = "Expected Ok")]
    fn test_assert_ok_fails() {
        let result: FcpResult<i32> = Err(FcpError::NotConfigured);
        assert_ok(&result);
    }

    #[test]
    fn test_assert_err_passes() {
        let result: FcpResult<i32> = Err(FcpError::NotConfigured);
        assert_err(&result);
    }

    #[test]
    #[should_panic(expected = "Expected Err")]
    fn test_assert_err_fails() {
        let result: FcpResult<i32> = Ok(42);
        assert_err(&result);
    }

    // ---- assert_error_type ----

    #[test]
    fn test_assert_error_type_passes() {
        let result: FcpResult<i32> = Err(FcpError::NotConfigured);
        assert_error_type(&result, "NotConfigured");
    }

    #[test]
    #[should_panic(expected = "Expected error containing")]
    fn test_assert_error_type_wrong_type() {
        let result: FcpResult<i32> = Err(FcpError::NotConfigured);
        assert_error_type(&result, "RateLimited");
    }

    #[test]
    #[should_panic(expected = "Expected error")]
    fn test_assert_error_type_ok() {
        let result: FcpResult<i32> = Ok(42);
        assert_error_type(&result, "NotConfigured");
    }

    // ---- assert_not_configured ----

    #[test]
    fn test_assert_not_configured_passes() {
        let result: FcpResult<i32> = Err(FcpError::NotConfigured);
        assert_not_configured(&result);
    }

    #[test]
    #[should_panic(expected = "Expected NotConfigured")]
    fn test_assert_not_configured_wrong_error() {
        let result: FcpResult<i32> = Err(FcpError::NotHandshaken);
        assert_not_configured(&result);
    }

    // ---- assert_not_handshaken ----

    #[test]
    fn test_assert_not_handshaken_passes() {
        let result: FcpResult<i32> = Err(FcpError::NotHandshaken);
        assert_not_handshaken(&result);
    }

    #[test]
    #[should_panic(expected = "Expected NotHandshaken")]
    fn test_assert_not_handshaken_wrong_error() {
        let result: FcpResult<i32> = Err(FcpError::NotConfigured);
        assert_not_handshaken(&result);
    }

    // ---- Health assertions ----

    fn ready_snapshot() -> HealthSnapshot {
        HealthSnapshot {
            status: HealthState::Ready,
            uptime_ms: 1000,
            load: None,
            details: None,
            rate_limit: None,
        }
    }

    fn degraded_snapshot(reason: &str) -> HealthSnapshot {
        HealthSnapshot {
            status: HealthState::Degraded {
                reason: reason.into(),
            },
            uptime_ms: 1000,
            load: None,
            details: None,
            rate_limit: None,
        }
    }

    fn error_snapshot(reason: &str) -> HealthSnapshot {
        HealthSnapshot {
            status: HealthState::Error {
                reason: reason.into(),
            },
            uptime_ms: 1000,
            load: None,
            details: None,
            rate_limit: None,
        }
    }

    fn test_response(result: Option<serde_json::Value>) -> InvokeResponse {
        use fcp_prelude::RequestId;
        let mut resp = InvokeResponse::ok(RequestId::new("test-req"), serde_json::json!(null));
        resp.result = result;
        resp
    }

    #[test]
    fn test_assert_healthy() {
        assert_healthy(&ready_snapshot());
    }

    #[test]
    #[should_panic(expected = "Expected Ready")]
    fn test_assert_healthy_fails_on_degraded() {
        assert_healthy(&degraded_snapshot("test"));
    }

    #[test]
    fn test_assert_degraded() {
        assert_degraded(&degraded_snapshot("slow"));
    }

    #[test]
    #[should_panic(expected = "Expected Degraded")]
    fn test_assert_degraded_fails_on_ready() {
        assert_degraded(&ready_snapshot());
    }

    #[test]
    fn test_assert_unhealthy() {
        assert_unhealthy(&error_snapshot("down"));
    }

    #[test]
    #[should_panic(expected = "Expected Error")]
    fn test_assert_unhealthy_fails_on_ready() {
        assert_unhealthy(&ready_snapshot());
    }

    // ---- InvokeResponse assertions ----

    #[test]
    fn test_assert_has_result() {
        let response = test_response(Some(serde_json::json!({"id": 1})));
        assert_has_result(&response);
    }

    #[test]
    #[should_panic(expected = "Expected result but got JSON null")]
    fn test_assert_has_result_null() {
        let response = test_response(Some(serde_json::Value::Null));
        assert_has_result(&response);
    }

    #[test]
    #[should_panic(expected = "Expected result but got None")]
    fn test_assert_has_result_none() {
        let response = test_response(None);
        assert_has_result(&response);
    }

    #[test]
    fn test_assert_no_result_none() {
        let response = test_response(None);
        assert_no_result(&response);
    }

    #[test]
    fn test_assert_no_result_null() {
        let response = test_response(Some(serde_json::Value::Null));
        assert_no_result(&response);
    }

    #[test]
    #[should_panic(expected = "Expected null result")]
    fn test_assert_no_result_has_value() {
        let response = test_response(Some(serde_json::json!(42)));
        assert_no_result(&response);
    }

    #[test]
    fn test_assert_result_has_field() {
        let response = test_response(Some(serde_json::json!({"name": "test", "id": 1})));
        assert_result_has_field(&response, "name");
        assert_result_has_field(&response, "id");
    }

    #[test]
    #[should_panic(expected = "Expected field")]
    fn test_assert_result_has_field_missing() {
        let response = test_response(Some(serde_json::json!({"name": "test"})));
        assert_result_has_field(&response, "missing");
    }

    #[test]
    fn test_assert_result_field_eq() {
        let response = test_response(Some(serde_json::json!({"count": 42})));
        assert_result_field_eq(&response, "count", &serde_json::json!(42));
    }

    #[test]
    #[should_panic(expected = "Expected field")]
    fn test_assert_result_field_eq_mismatch() {
        let response = test_response(Some(serde_json::json!({"count": 42})));
        assert_result_field_eq(&response, "count", &serde_json::json!(99));
    }

    // ---- JSON assertions ----

    #[test]
    fn test_assert_json_eq_passes() {
        let a = serde_json::json!({"x": 1, "y": [2, 3]});
        let b = serde_json::json!({"x": 1, "y": [2, 3]});
        assert_json_eq(&a, &b);
    }

    #[test]
    #[should_panic(expected = "JSON values don't match")]
    fn test_assert_json_eq_fails() {
        let a = serde_json::json!({"x": 1});
        let b = serde_json::json!({"x": 2});
        assert_json_eq(&a, &b);
    }

    #[test]
    fn test_assert_json_string_contains() {
        let val = serde_json::json!("hello world");
        assert_json_string_contains(&val, "world");
    }

    #[test]
    #[should_panic(expected = "Expected string containing")]
    fn test_assert_json_string_contains_fails() {
        let val = serde_json::json!("hello");
        assert_json_string_contains(&val, "world");
    }

    #[test]
    fn test_assert_json_has_nested() {
        let json = serde_json::json!({
            "a": { "b": { "c": 42 } }
        });
        assert_json_has(&json, "a.b.c");
    }

    // ---- Additional JSON assertions ----

    #[test]
    fn test_assert_json_has_single_field() {
        let json = serde_json::json!({"name": "test"});
        assert_json_has(&json, "name");
    }

    #[test]
    #[should_panic(expected = "Missing field")]
    fn test_assert_json_has_deeply_nested_missing() {
        let json = serde_json::json!({"a": {"b": {}}});
        assert_json_has(&json, "a.b.c");
    }

    #[test]
    fn test_assert_json_eq_null_values() {
        let a = serde_json::json!(null);
        let b = serde_json::json!(null);
        assert_json_eq(&a, &b);
    }

    #[test]
    fn test_assert_json_eq_arrays() {
        let a = serde_json::json!([1, 2, 3]);
        let b = serde_json::json!([1, 2, 3]);
        assert_json_eq(&a, &b);
    }

    #[test]
    fn test_assert_json_eq_nested_objects() {
        let a = serde_json::json!({"x": {"y": {"z": true}}});
        let b = serde_json::json!({"x": {"y": {"z": true}}});
        assert_json_eq(&a, &b);
    }

    #[test]
    fn test_assert_json_array_len_one() {
        let json = serde_json::json!([42]);
        assert_json_array_len(&json, 1);
    }

    #[test]
    fn test_assert_json_string_contains_exact_match() {
        let val = serde_json::json!("exact");
        assert_json_string_contains(&val, "exact");
    }

    #[test]
    fn test_assert_json_string_contains_substring() {
        let val = serde_json::json!("prefix-middle-suffix");
        assert_json_string_contains(&val, "middle");
    }

    #[test]
    #[should_panic(expected = "Expected JSON string")]
    fn test_assert_json_string_contains_not_string() {
        let val = serde_json::json!(42);
        assert_json_string_contains(&val, "anything");
    }

    // ---- Additional result assertions ----

    #[test]
    fn test_assert_ok_with_string_value() {
        let result: FcpResult<String> = Ok("success".to_string());
        assert_ok(&result);
    }

    #[test]
    fn test_assert_err_with_invalid_request() {
        let result: FcpResult<()> = Err(FcpError::InvalidRequest {
            code: 400,
            message: "bad input".to_string(),
        });
        assert_err(&result);
    }

    #[test]
    fn test_assert_error_type_invalid_request() {
        let result: FcpResult<()> = Err(FcpError::InvalidRequest {
            code: 400,
            message: "bad".to_string(),
        });
        assert_error_type(&result, "InvalidRequest");
    }

    // ---- Additional health assertions ----

    #[test]
    #[should_panic(expected = "Expected Error")]
    fn test_assert_unhealthy_fails_on_degraded() {
        assert_unhealthy(&degraded_snapshot("slow"));
    }

    #[test]
    #[should_panic(expected = "Expected Degraded")]
    fn test_assert_degraded_fails_on_error() {
        assert_degraded(&error_snapshot("down"));
    }

    // ---- Additional InvokeResponse assertions ----

    #[test]
    fn test_assert_result_field_eq_string() {
        let response = test_response(Some(serde_json::json!({"name": "test"})));
        assert_result_field_eq(&response, "name", &serde_json::json!("test"));
    }

    #[test]
    fn test_assert_result_field_eq_missing_field_is_null() {
        let response = test_response(Some(serde_json::json!({"a": 1})));
        assert_result_field_eq(&response, "b", &serde_json::Value::Null);
    }

    #[test]
    fn test_assert_has_result_with_object() {
        let response = test_response(Some(serde_json::json!({"items": [1, 2, 3]})));
        assert_has_result(&response);
    }

    #[test]
    fn test_assert_result_has_field_nested_not_required() {
        // assert_result_has_field only checks top-level fields
        let response = test_response(Some(serde_json::json!({"outer": {"inner": 1}})));
        assert_result_has_field(&response, "outer");
    }

    // ---- Timing assertions ----

    #[fcp_async_core::runtime::test]
    async fn test_assert_completes_within() {
        let result = assert_completes_within(async { 42 }, std::time::Duration::from_secs(1)).await;
        assert_eq!(result, 42);
    }

    // ---- Edge case: assert_json_has with single-key object ----

    #[test]
    fn test_assert_json_has_top_level_array_index_not_supported() {
        // assert_json_has uses dot-split, so array indices are just keys
        let json = serde_json::json!({"0": "zero"});
        assert_json_has(&json, "0");
    }

    #[test]
    fn test_assert_json_eq_empty_objects() {
        let a = serde_json::json!({});
        let b = serde_json::json!({});
        assert_json_eq(&a, &b);
    }

    #[test]
    fn test_assert_json_eq_empty_arrays() {
        let a = serde_json::json!([]);
        let b = serde_json::json!([]);
        assert_json_eq(&a, &b);
    }

    #[test]
    fn test_assert_json_eq_booleans() {
        assert_json_eq(&serde_json::json!(true), &serde_json::json!(true));
        assert_json_eq(&serde_json::json!(false), &serde_json::json!(false));
    }

    #[test]
    #[should_panic(expected = "JSON values don't match")]
    fn test_assert_json_eq_bool_mismatch() {
        assert_json_eq(&serde_json::json!(true), &serde_json::json!(false));
    }

    #[test]
    fn test_assert_json_string_contains_unicode() {
        let val = serde_json::json!("caf\u{00e9} au lait");
        assert_json_string_contains(&val, "caf\u{00e9}");
    }

    #[test]
    fn test_assert_json_string_contains_empty_pattern() {
        let val = serde_json::json!("anything");
        assert_json_string_contains(&val, "");
    }

    #[test]
    fn test_assert_json_array_len_large() {
        let arr: Vec<i32> = (0..100).collect();
        let json = serde_json::json!(arr);
        assert_json_array_len(&json, 100);
    }

    #[test]
    #[should_panic(expected = "Expected JSON array")]
    fn test_assert_json_array_len_not_array() {
        let json = serde_json::json!({"not": "array"});
        assert_json_array_len(&json, 0);
    }

    #[test]
    fn test_assert_ok_with_unit() {
        let result: FcpResult<()> = Ok(());
        assert_ok(&result);
    }

    #[test]
    #[should_panic(expected = "Expected NotConfigured")]
    fn test_assert_not_configured_on_ok() {
        let result: FcpResult<i32> = Ok(42);
        assert_not_configured(&result);
    }

    #[test]
    #[should_panic(expected = "Expected NotHandshaken")]
    fn test_assert_not_handshaken_on_ok() {
        let result: FcpResult<i32> = Ok(42);
        assert_not_handshaken(&result);
    }
}
