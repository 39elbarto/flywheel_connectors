//! Pipeline conditional branching and error handling.
//!
//! Adds conditional execution and error handling to pipeline step definitions.
//! Conditions are simple expressions evaluated against step outputs stored in a
//! [`PipelineContext`].  Error modes control what happens when a step fails.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Comparison operator ─────────────────────────────────────────────────────

/// Relational comparison operators.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompareOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl fmt::Display for CompareOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Lt => "<",
            Self::Lte => "<=",
        };
        f.write_str(s)
    }
}

// ── Condition value ─────────────────────────────────────────────────────────

/// A literal value on the right-hand side of a comparison.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ConditionValue {
    String(String),
    Number(f64),
    Bool(bool),
    Null,
}

impl fmt::Display for ConditionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "'{s}'"),
            Self::Number(n) => write!(f, "{n}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Null => f.write_str("null"),
        }
    }
}

// ── Condition expression AST ────────────────────────────────────────────────

/// Parsed condition expression.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ConditionExpr {
    /// Truthy check on a template path (e.g. `"{{steps.fetch.output}}"`).
    Truthy(String),
    /// Comparison between a template path and a literal value.
    Comparison {
        left: String,
        op: CompareOp,
        right: ConditionValue,
    },
    /// Logical AND of two sub-expressions.
    LogicalAnd(Box<Self>, Box<Self>),
    /// Logical OR of two sub-expressions.
    LogicalOr(Box<Self>, Box<Self>),
    /// Logical NOT of a sub-expression.
    Not(Box<Self>),
    /// Length check: `{{path | length}} op value`.
    LengthCheck {
        path: String,
        op: CompareOp,
        value: usize,
    },
    /// Contains check: `{{haystack}} contains 'needle'`.
    Contains { haystack: String, needle: String },
    /// Always true – useful for testing.
    Always,
    /// Always false – useful for testing.
    Never,
}

/// A parsed condition retaining the raw source string.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Condition {
    pub raw: String,
    pub parsed: ConditionExpr,
}

// ── Error handling types ────────────────────────────────────────────────────

/// How a pipeline step should behave when it fails.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorMode {
    /// Skip the failed step and continue.
    Skip,
    /// Abort the whole pipeline.
    #[default]
    Abort,
    /// Retry up to `max_attempts` times.
    Retry { max_attempts: u32 },
    /// Run a fallback step instead.
    Fallback { step_id: String },
}

/// Decision returned by [`apply_error_mode`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorDecision {
    Skip,
    Abort,
    Retry,
    RunFallback(String),
}

// ── Step outcome ────────────────────────────────────────────────────────────

/// Result of executing (or skipping) a single pipeline step.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StepOutcome {
    /// Step executed successfully, producing a JSON value.
    Executed(Value),
    /// Step was skipped with a reason string.
    Skipped(String),
    /// Step failed.
    Failed(StepError),
}

/// Error information for a failed step.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepError {
    pub step_id: String,
    pub error_type: String,
    pub message: String,
    pub attempt: u32,
}

impl fmt::Display for StepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "step '{}' failed (attempt {}): [{}] {}",
            self.step_id, self.attempt, self.error_type, self.message
        )
    }
}

// ── Execution trace ─────────────────────────────────────────────────────────

/// Trace of a full pipeline execution.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExecutionTrace {
    pub steps: Vec<StepTraceEntry>,
}

/// Single entry in an execution trace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepTraceEntry {
    pub step_id: String,
    pub outcome: StepOutcome,
    pub condition_result: Option<bool>,
    pub error_mode: ErrorMode,
    pub duration_ms: u64,
    pub attempt: u32,
}

// ── Pipeline context ────────────────────────────────────────────────────────

/// Holds step outputs for condition evaluation.
#[derive(Clone, Debug, Default)]
pub struct PipelineContext {
    outputs: BTreeMap<String, Value>,
}

impl PipelineContext {
    /// Create a new empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the output of a step.
    pub fn set_output(&mut self, step_id: impl Into<String>, value: Value) {
        self.outputs.insert(step_id.into(), value);
    }

    /// Retrieve a step's output.
    #[must_use]
    pub fn get_output(&self, step_id: &str) -> Option<&Value> {
        self.outputs.get(step_id)
    }
}

// ── Template-path resolution ────────────────────────────────────────────────

/// Resolve a dot-separated path (with optional array indices) against the
/// pipeline context.
///
/// Paths have the form `steps.<step_id>.output[.field[.field|[N]]*]`.
#[must_use]
pub fn resolve_template_path(path: &str, context: &PipelineContext) -> Option<Value> {
    // Expected: "steps.<id>.output..." or just "<id>.output..."
    let segments = split_path(path);
    if segments.is_empty() {
        return None;
    }

    // Determine step id and the remainder.
    let (step_id, rest_start) = if segments[0] == "steps" {
        if segments.len() < 3 {
            return None;
        }
        (&segments[1], 3) // skip "steps", id, "output"
    } else if segments.len() >= 2 && segments[1] == "output" {
        (&segments[0], 2)
    } else {
        return None;
    };

    let root = context.get_output(step_id.as_str())?;
    let mut current = root.clone();

    for seg in &segments[rest_start..] {
        // Try array index.
        if let Ok(idx) = seg.parse::<usize>() {
            current = current.as_array()?.get(idx)?.clone();
        } else {
            current = current.as_object()?.get(seg.as_str())?.clone();
        }
    }

    Some(current)
}

/// Split a path on `.` while also splitting `foo[N]` into `["foo", "N"]`.
fn split_path(path: &str) -> Vec<String> {
    let mut result = Vec::new();
    for segment in path.split('.') {
        if let Some(bracket_pos) = segment.find('[') {
            let name = &segment[..bracket_pos];
            if !name.is_empty() {
                result.push(name.to_owned());
            }
            // Parse potential index: `[0]`
            let rest = &segment[bracket_pos..];
            for part in rest.split('[') {
                let part = part.trim_end_matches(']');
                if !part.is_empty() {
                    result.push(part.to_owned());
                }
            }
        } else {
            result.push(segment.to_owned());
        }
    }
    result
}

// ── Condition parsing ───────────────────────────────────────────────────────

/// Parse a condition string into a [`Condition`].
///
/// # Errors
///
/// Returns an error if the expression has invalid syntax.
pub fn parse_condition(s: &str) -> Result<Condition, ConditionParseError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(ConditionParseError::Empty);
    }
    let parsed = parse_expr(trimmed)?;
    Ok(Condition {
        raw: s.to_owned(),
        parsed,
    })
}

/// Condition parse error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConditionParseError {
    Empty,
    InvalidSyntax(String),
}

impl fmt::Display for ConditionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty condition expression"),
            Self::InvalidSyntax(msg) => write!(f, "invalid condition syntax: {msg}"),
        }
    }
}

impl std::error::Error for ConditionParseError {}

/// Top-level expression parser.  Handles `||` at the lowest precedence.
fn parse_expr(s: &str) -> Result<ConditionExpr, ConditionParseError> {
    // Split on `||` outside of template braces.
    if let Some((left, right)) = split_logical(s, "||") {
        let l = parse_expr(left.trim())?;
        let r = parse_expr(right.trim())?;
        return Ok(ConditionExpr::LogicalOr(Box::new(l), Box::new(r)));
    }
    parse_and(s)
}

/// Parse `&&` (higher precedence than `||`).
fn parse_and(s: &str) -> Result<ConditionExpr, ConditionParseError> {
    if let Some((left, right)) = split_logical(s, "&&") {
        let l = parse_and(left.trim())?;
        let r = parse_and(right.trim())?;
        return Ok(ConditionExpr::LogicalAnd(Box::new(l), Box::new(r)));
    }
    parse_unary(s)
}

/// Parse unary `!` prefix.
fn parse_unary(s: &str) -> Result<ConditionExpr, ConditionParseError> {
    let trimmed = s.trim();
    if let Some(rest) = trimmed.strip_prefix('!') {
        let inner = parse_unary(rest.trim())?;
        return Ok(ConditionExpr::Not(Box::new(inner)));
    }
    parse_atom(s)
}

/// Parse a single atom: comparison, length check, contains, or truthy.
fn parse_atom(s: &str) -> Result<ConditionExpr, ConditionParseError> {
    let trimmed = s.trim();

    // "always" / "never" literals.
    if trimmed.eq_ignore_ascii_case("always") {
        return Ok(ConditionExpr::Always);
    }
    if trimmed.eq_ignore_ascii_case("never") {
        return Ok(ConditionExpr::Never);
    }

    // Length check: "{{path | length}} op N"
    if let Some(cond) = try_parse_length(trimmed)? {
        return Ok(cond);
    }

    // Contains: "{{path}} contains 'needle'"
    if let Some(cond) = try_parse_contains(trimmed)? {
        return Ok(cond);
    }

    // Comparison: "{{path}} op value"
    if let Some(cond) = try_parse_comparison(trimmed)? {
        return Ok(cond);
    }

    // Truthy: bare template reference.
    if let Some(path) = extract_template_path(trimmed) {
        return Ok(ConditionExpr::Truthy(path));
    }

    Err(ConditionParseError::InvalidSyntax(format!(
        "cannot parse: {trimmed}"
    )))
}

/// Try to parse a length check expression.
fn try_parse_length(s: &str) -> Result<Option<ConditionExpr>, ConditionParseError> {
    // Pattern: "{{<path> | length}} <op> <n>"
    let Some(rest) = s.strip_prefix("{{") else {
        return Ok(None);
    };
    let Some(pipe_pos) = rest.find("| length}}") else {
        return Ok(None);
    };
    let path = rest[..pipe_pos].trim().to_owned();
    let after = rest[pipe_pos + "| length}}".len()..].trim();

    let (op, value_str) = parse_op_and_rest(after)?;
    let value: usize = value_str.trim().parse().map_err(|_| {
        ConditionParseError::InvalidSyntax(format!("bad length value: {value_str}"))
    })?;

    Ok(Some(ConditionExpr::LengthCheck { path, op, value }))
}

/// Try to parse a `contains` expression.
fn try_parse_contains(s: &str) -> Result<Option<ConditionExpr>, ConditionParseError> {
    // Pattern: "{{haystack}} contains 'needle'"
    let Some(template_end) = s.find("}}") else {
        return Ok(None);
    };
    let after = s[template_end + 2..].trim();
    if !after.starts_with("contains ") {
        return Ok(None);
    }
    let haystack = extract_template_path(&s[..template_end + 2])
        .ok_or_else(|| ConditionParseError::InvalidSyntax("bad template in contains".to_owned()))?;
    let needle_raw = after["contains ".len()..].trim();
    let needle = parse_string_literal(needle_raw).ok_or_else(|| {
        ConditionParseError::InvalidSyntax(format!("bad needle in contains: {needle_raw}"))
    })?;
    Ok(Some(ConditionExpr::Contains { haystack, needle }))
}

/// Try to parse a comparison expression.
fn try_parse_comparison(s: &str) -> Result<Option<ConditionExpr>, ConditionParseError> {
    let Some(template_end) = s.find("}}") else {
        return Ok(None);
    };
    let left = extract_template_path(&s[..template_end + 2]).ok_or_else(|| {
        ConditionParseError::InvalidSyntax("bad template in comparison".to_owned())
    })?;
    let after = s[template_end + 2..].trim();
    if after.is_empty() {
        // Just a template – this is a truthy check, not a comparison.
        return Ok(None);
    }
    let (op, value_str) = parse_op_and_rest(after)?;
    let right = parse_condition_value(value_str.trim())?;
    Ok(Some(ConditionExpr::Comparison { left, op, right }))
}

/// Extract the template path from `{{path}}`.
fn extract_template_path(s: &str) -> Option<String> {
    let trimmed = s.trim();
    let inner = trimmed.strip_prefix("{{")?;
    let inner = inner.strip_suffix("}}")?;
    let path = inner.trim();
    if path.is_empty() {
        return None;
    }
    Some(path.to_owned())
}

/// Parse a comparison operator at the start of a string, returning (op, rest).
fn parse_op_and_rest(s: &str) -> Result<(CompareOp, &str), ConditionParseError> {
    let s = s.trim();
    // Order matters: check two-char operators before single-char.
    for (prefix, op) in [
        ("==", CompareOp::Eq),
        ("!=", CompareOp::Ne),
        (">=", CompareOp::Gte),
        ("<=", CompareOp::Lte),
        (">", CompareOp::Gt),
        ("<", CompareOp::Lt),
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return Ok((op, rest));
        }
    }
    Err(ConditionParseError::InvalidSyntax(format!(
        "expected comparison operator in: {s}"
    )))
}

/// Parse a literal condition value.
fn parse_condition_value(s: &str) -> Result<ConditionValue, ConditionParseError> {
    let trimmed = s.trim();
    if trimmed == "null" {
        return Ok(ConditionValue::Null);
    }
    if trimmed == "true" {
        return Ok(ConditionValue::Bool(true));
    }
    if trimmed == "false" {
        return Ok(ConditionValue::Bool(false));
    }
    if let Some(string) = parse_string_literal(trimmed) {
        return Ok(ConditionValue::String(string));
    }
    if let Ok(n) = trimmed.parse::<f64>() {
        return Ok(ConditionValue::Number(n));
    }
    Err(ConditionParseError::InvalidSyntax(format!(
        "cannot parse value: {trimmed}"
    )))
}

/// Parse a single-quoted or double-quoted string literal, returning the inner
/// content.
fn parse_string_literal(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if ((trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || (trimmed.starts_with('"') && trimmed.ends_with('"')))
        && trimmed.len() >= 2
    {
        return Some(trimmed[1..trimmed.len() - 1].to_owned());
    }
    None
}

/// Split on a logical operator (`&&` or `||`) that is not inside `{{ }}`.
fn split_logical<'a>(s: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    let mut depth: u32 = 0;
    let bytes = s.as_bytes();
    let op_bytes = op.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            depth += 1;
            i += 2;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'}' && bytes[i + 1] == b'}' {
            depth = depth.saturating_sub(1);
            i += 2;
            continue;
        }
        if depth == 0
            && i + op_bytes.len() <= bytes.len()
            && &bytes[i..i + op_bytes.len()] == op_bytes
        {
            return Some((&s[..i], &s[i + op_bytes.len()..]));
        }
        i += 1;
    }
    None
}

// ── Condition evaluation ────────────────────────────────────────────────────

/// Evaluate a condition expression against a pipeline context.
///
/// # Errors
///
/// Returns an error when a referenced step output is missing.
pub fn evaluate_condition(
    cond: &ConditionExpr,
    context: &PipelineContext,
) -> Result<bool, ConditionEvalError> {
    match cond {
        ConditionExpr::Always => Ok(true),
        ConditionExpr::Never => Ok(false),
        ConditionExpr::Truthy(path) => {
            let val = resolve_template_path(path, context);
            Ok(is_truthy(val.as_ref()))
        }
        ConditionExpr::Comparison { left, op, right } => {
            let val = resolve_template_path(left, context)
                .ok_or_else(|| ConditionEvalError::MissingStep { path: left.clone() })?;
            Ok(compare_value(&val, op, right))
        }
        ConditionExpr::LogicalAnd(l, r) => {
            let lv = evaluate_condition(l, context)?;
            let rv = evaluate_condition(r, context)?;
            Ok(lv && rv)
        }
        ConditionExpr::LogicalOr(l, r) => {
            let lv = evaluate_condition(l, context)?;
            let rv = evaluate_condition(r, context)?;
            Ok(lv || rv)
        }
        ConditionExpr::Not(inner) => {
            let v = evaluate_condition(inner, context)?;
            Ok(!v)
        }
        ConditionExpr::LengthCheck { path, op, value } => {
            let val = resolve_template_path(path, context)
                .ok_or_else(|| ConditionEvalError::MissingStep { path: path.clone() })?;
            let len = value_length(&val);
            Ok(compare_usize(len, op, *value))
        }
        ConditionExpr::Contains { haystack, needle } => {
            let val = resolve_template_path(haystack, context).ok_or_else(|| {
                ConditionEvalError::MissingStep {
                    path: haystack.clone(),
                }
            })?;
            Ok(value_contains(&val, needle))
        }
    }
}

/// Condition evaluation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConditionEvalError {
    MissingStep { path: String },
}

impl fmt::Display for ConditionEvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingStep { path } => write!(f, "missing step output for path: {path}"),
        }
    }
}

impl std::error::Error for ConditionEvalError {}

/// Determine truthiness of an optional JSON value.
fn is_truthy(val: Option<&Value>) -> bool {
    match val {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|v| v != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// Compare a JSON value against a [`ConditionValue`] using the given operator.
fn compare_value(val: &Value, op: &CompareOp, right: &ConditionValue) -> bool {
    match right {
        ConditionValue::Null => {
            let is_null = val.is_null();
            match op {
                CompareOp::Eq => is_null,
                CompareOp::Ne => !is_null,
                _ => false,
            }
        }
        ConditionValue::Bool(b) => {
            let Some(lv) = val.as_bool() else {
                return false;
            };
            match op {
                CompareOp::Eq => lv == *b,
                CompareOp::Ne => lv != *b,
                _ => false,
            }
        }
        ConditionValue::String(s) => {
            let Some(lv) = val.as_str() else {
                return false;
            };
            match op {
                CompareOp::Eq => lv == s,
                CompareOp::Ne => lv != s,
                CompareOp::Gt => lv > s.as_str(),
                CompareOp::Gte => lv >= s.as_str(),
                CompareOp::Lt => lv < s.as_str(),
                CompareOp::Lte => lv <= s.as_str(),
            }
        }
        ConditionValue::Number(n) => {
            let Some(lv) = val.as_f64() else {
                return false;
            };
            match op {
                CompareOp::Eq => (lv - n).abs() < f64::EPSILON,
                CompareOp::Ne => (lv - n).abs() >= f64::EPSILON,
                CompareOp::Gt => lv > *n,
                CompareOp::Gte => lv >= *n,
                CompareOp::Lt => lv < *n,
                CompareOp::Lte => lv <= *n,
            }
        }
    }
}

/// Get the "length" of a JSON value (array length, string length, or 0).
fn value_length(val: &Value) -> usize {
    match val {
        Value::Array(a) => a.len(),
        Value::String(s) => s.len(),
        Value::Object(o) => o.len(),
        _ => 0,
    }
}

/// Compare two `usize` values.
const fn compare_usize(left: usize, op: &CompareOp, right: usize) -> bool {
    match op {
        CompareOp::Eq => left == right,
        CompareOp::Ne => left != right,
        CompareOp::Gt => left > right,
        CompareOp::Gte => left >= right,
        CompareOp::Lt => left < right,
        CompareOp::Lte => left <= right,
    }
}

/// Check whether a JSON value "contains" a needle string.
fn value_contains(val: &Value, needle: &str) -> bool {
    match val {
        Value::String(s) => s.contains(needle),
        Value::Array(arr) => arr.iter().any(|v| v.as_str().is_some_and(|s| s == needle)),
        _ => false,
    }
}

// ── Error mode parsing ──────────────────────────────────────────────────────

/// Parse an error mode specification string.
///
/// Accepted forms: `"skip"`, `"abort"`, `"retry(N)"`, `"fallback(step_id)"`.
///
/// # Errors
///
/// Returns an error for unrecognised or malformed mode strings.
pub fn parse_error_mode(s: &str) -> Result<ErrorMode, ErrorModeParseError> {
    let trimmed = s.trim();
    match trimmed {
        "skip" => Ok(ErrorMode::Skip),
        "abort" => Ok(ErrorMode::Abort),
        _ if trimmed.starts_with("retry(") && trimmed.ends_with(')') => {
            let inner = &trimmed[6..trimmed.len() - 1];
            let n: u32 = inner.parse().map_err(|_| ErrorModeParseError {
                input: s.to_owned(),
                reason: format!("invalid retry count: {inner}"),
            })?;
            if n == 0 {
                return Err(ErrorModeParseError {
                    input: s.to_owned(),
                    reason: "retry count must be > 0".to_owned(),
                });
            }
            Ok(ErrorMode::Retry { max_attempts: n })
        }
        _ if trimmed.starts_with("fallback(") && trimmed.ends_with(')') => {
            let inner = &trimmed[9..trimmed.len() - 1].trim();
            if inner.is_empty() {
                return Err(ErrorModeParseError {
                    input: s.to_owned(),
                    reason: "fallback step_id cannot be empty".to_owned(),
                });
            }
            Ok(ErrorMode::Fallback {
                step_id: (*inner).to_owned(),
            })
        }
        _ => Err(ErrorModeParseError {
            input: s.to_owned(),
            reason: format!("unrecognised error mode: {trimmed}"),
        }),
    }
}

/// Error mode parse error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorModeParseError {
    pub input: String,
    pub reason: String,
}

impl fmt::Display for ErrorModeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad error mode '{}': {}", self.input, self.reason)
    }
}

impl std::error::Error for ErrorModeParseError {}

// ── Error mode application ──────────────────────────────────────────────────

/// Given an error mode, the error, and the current attempt number, decide what
/// to do next.
#[must_use]
pub fn apply_error_mode(mode: &ErrorMode, _error: &StepError, attempt: u32) -> ErrorDecision {
    match mode {
        ErrorMode::Skip => ErrorDecision::Skip,
        ErrorMode::Abort => ErrorDecision::Abort,
        ErrorMode::Retry { max_attempts } => {
            if attempt < *max_attempts {
                ErrorDecision::Retry
            } else {
                ErrorDecision::Abort
            }
        }
        ErrorMode::Fallback { step_id } => ErrorDecision::RunFallback(step_id.clone()),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── helpers ─────────────────────────────────────────────────────────

    fn ctx_with_fetch() -> PipelineContext {
        let mut ctx = PipelineContext::new();
        ctx.set_output(
            "fetch",
            json!({
                "issues": [
                    {"title": "Bug A", "status": "open"},
                    {"title": "Bug B", "status": "closed"}
                ],
                "count": 2,
                "ready": true,
                "status": "active",
                "message": "all good",
                "tags": ["rust", "fcp", "pipeline"]
            }),
        );
        ctx
    }

    fn step_error(id: &str, attempt: u32) -> StepError {
        StepError {
            step_id: id.to_owned(),
            error_type: "runtime".to_owned(),
            message: "connection refused".to_owned(),
            attempt,
        }
    }

    // ── Condition parsing: truthy ───────────────────────────────────────

    #[test]
    fn pipeline_cond_parse_truthy() {
        let c = parse_condition("{{steps.fetch.output}}").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Truthy("steps.fetch.output".to_owned())
        );
    }

    #[test]
    fn pipeline_cond_parse_truthy_with_path() {
        let c = parse_condition("{{steps.fetch.output.ready}}").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Truthy("steps.fetch.output.ready".to_owned())
        );
    }

    // ── Condition parsing: comparison operators ─────────────────────────

    #[test]
    fn pipeline_cond_parse_comparison_eq() {
        let c = parse_condition("{{steps.check.output.status}} == 'active'").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Comparison {
                left: "steps.check.output.status".to_owned(),
                op: CompareOp::Eq,
                right: ConditionValue::String("active".to_owned()),
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_comparison_ne() {
        let c = parse_condition("{{steps.a.output.x}} != 'bad'").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Comparison {
                left: "steps.a.output.x".to_owned(),
                op: CompareOp::Ne,
                right: ConditionValue::String("bad".to_owned()),
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_comparison_gt() {
        let c = parse_condition("{{steps.data.output.count}} > 5").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Comparison {
                left: "steps.data.output.count".to_owned(),
                op: CompareOp::Gt,
                right: ConditionValue::Number(5.0),
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_comparison_gte() {
        let c = parse_condition("{{steps.data.output.count}} >= 10").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Comparison {
                left: "steps.data.output.count".to_owned(),
                op: CompareOp::Gte,
                right: ConditionValue::Number(10.0),
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_comparison_lt() {
        let c = parse_condition("{{steps.data.output.count}} < 3").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Comparison {
                left: "steps.data.output.count".to_owned(),
                op: CompareOp::Lt,
                right: ConditionValue::Number(3.0),
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_comparison_lte() {
        let c = parse_condition("{{steps.data.output.count}} <= 100").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Comparison {
                left: "steps.data.output.count".to_owned(),
                op: CompareOp::Lte,
                right: ConditionValue::Number(100.0),
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_comparison_bool_true() {
        let c = parse_condition("{{steps.x.output.flag}} == true").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Comparison {
                left: "steps.x.output.flag".to_owned(),
                op: CompareOp::Eq,
                right: ConditionValue::Bool(true),
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_comparison_null() {
        let c = parse_condition("{{steps.x.output.val}} == null").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Comparison {
                left: "steps.x.output.val".to_owned(),
                op: CompareOp::Eq,
                right: ConditionValue::Null,
            }
        );
    }

    // ── Condition parsing: logical operators ────────────────────────────

    #[test]
    fn pipeline_cond_parse_logical_and() {
        let c = parse_condition(
            "{{steps.data.output.count}} >= 10 && {{steps.data.output.ready}} == true",
        )
        .unwrap();
        match &c.parsed {
            ConditionExpr::LogicalAnd(l, r) => {
                assert!(matches!(
                    l.as_ref(),
                    ConditionExpr::Comparison {
                        op: CompareOp::Gte,
                        ..
                    }
                ));
                assert!(matches!(
                    r.as_ref(),
                    ConditionExpr::Comparison {
                        op: CompareOp::Eq,
                        ..
                    }
                ));
            }
            other => panic!("expected LogicalAnd, got {other:?}"),
        }
    }

    #[test]
    fn pipeline_cond_parse_logical_or() {
        let c = parse_condition("{{steps.a.output.x}} == 'yes' || {{steps.b.output.y}} == 'yes'")
            .unwrap();
        assert!(matches!(c.parsed, ConditionExpr::LogicalOr(_, _)));
    }

    #[test]
    fn pipeline_cond_parse_logical_not() {
        let c = parse_condition("!{{steps.skip.output.should_skip}}").unwrap();
        match &c.parsed {
            ConditionExpr::Not(inner) => {
                assert!(matches!(inner.as_ref(), ConditionExpr::Truthy(_)));
            }
            other => panic!("expected Not, got {other:?}"),
        }
    }

    // ── Condition parsing: length ───────────────────────────────────────

    #[test]
    fn pipeline_cond_parse_length_gt() {
        let c = parse_condition("{{steps.fetch.output.issues | length}} > 0").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::LengthCheck {
                path: "steps.fetch.output.issues".to_owned(),
                op: CompareOp::Gt,
                value: 0,
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_length_eq() {
        let c = parse_condition("{{steps.fetch.output.items | length}} == 5").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::LengthCheck {
                path: "steps.fetch.output.items".to_owned(),
                op: CompareOp::Eq,
                value: 5,
            }
        );
    }

    // ── Condition parsing: contains ─────────────────────────────────────

    #[test]
    fn pipeline_cond_parse_contains() {
        let c = parse_condition("{{steps.fetch.output.message}} contains 'good'").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Contains {
                haystack: "steps.fetch.output.message".to_owned(),
                needle: "good".to_owned(),
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_contains_double_quotes() {
        let c = parse_condition("{{steps.a.output.text}} contains \"hello\"").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Contains {
                haystack: "steps.a.output.text".to_owned(),
                needle: "hello".to_owned(),
            }
        );
    }

    // ── Condition parsing: always / never ───────────────────────────────

    #[test]
    fn pipeline_cond_parse_always() {
        let c = parse_condition("always").unwrap();
        assert_eq!(c.parsed, ConditionExpr::Always);
    }

    #[test]
    fn pipeline_cond_parse_never() {
        let c = parse_condition("never").unwrap();
        assert_eq!(c.parsed, ConditionExpr::Never);
    }

    // ── Condition parsing: edge cases ───────────────────────────────────

    #[test]
    fn pipeline_cond_parse_empty() {
        let err = parse_condition("").unwrap_err();
        assert_eq!(err, ConditionParseError::Empty);
    }

    #[test]
    fn pipeline_cond_parse_whitespace_only() {
        let err = parse_condition("   ").unwrap_err();
        assert_eq!(err, ConditionParseError::Empty);
    }

    #[test]
    fn pipeline_cond_parse_invalid_syntax() {
        let err = parse_condition("gibberish").unwrap_err();
        assert!(matches!(err, ConditionParseError::InvalidSyntax(_)));
    }

    #[test]
    fn pipeline_cond_parse_preserves_raw() {
        let c = parse_condition("  always  ").unwrap();
        assert_eq!(c.raw, "  always  ");
    }

    // ── Condition evaluation: truthy ────────────────────────────────────

    #[test]
    fn pipeline_cond_eval_truthy_true() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::Truthy("steps.fetch.output.ready".to_owned());
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_truthy_false_missing() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::Truthy("steps.missing.output.x".to_owned());
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_truthy_false_null() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", Value::Null);
        let expr = ConditionExpr::Truthy("steps.s.output".to_owned());
        // The path "steps.s.output" resolves root which is null.
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    // ── Condition evaluation: comparison ────────────────────────────────

    #[test]
    fn pipeline_cond_eval_comparison_eq_true() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::Comparison {
            left: "steps.fetch.output.status".to_owned(),
            op: CompareOp::Eq,
            right: ConditionValue::String("active".to_owned()),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_comparison_eq_false() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::Comparison {
            left: "steps.fetch.output.status".to_owned(),
            op: CompareOp::Eq,
            right: ConditionValue::String("inactive".to_owned()),
        };
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_comparison_gt_number() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::Comparison {
            left: "steps.fetch.output.count".to_owned(),
            op: CompareOp::Gt,
            right: ConditionValue::Number(1.0),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_comparison_lte_number() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::Comparison {
            left: "steps.fetch.output.count".to_owned(),
            op: CompareOp::Lte,
            right: ConditionValue::Number(2.0),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_comparison_missing_step() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::Comparison {
            left: "steps.nope.output.x".to_owned(),
            op: CompareOp::Eq,
            right: ConditionValue::Number(0.0),
        };
        let err = evaluate_condition(&expr, &ctx).unwrap_err();
        assert_eq!(
            err,
            ConditionEvalError::MissingStep {
                path: "steps.nope.output.x".to_owned(),
            }
        );
    }

    #[test]
    fn pipeline_cond_eval_comparison_null() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": null}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Eq,
            right: ConditionValue::Null,
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    // ── Condition evaluation: logical ───────────────────────────────────

    #[test]
    fn pipeline_cond_eval_and_both_true() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::LogicalAnd(
            Box::new(ConditionExpr::Always),
            Box::new(ConditionExpr::Always),
        );
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_and_one_false() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::LogicalAnd(
            Box::new(ConditionExpr::Always),
            Box::new(ConditionExpr::Never),
        );
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_or_one_true() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::LogicalOr(
            Box::new(ConditionExpr::Never),
            Box::new(ConditionExpr::Always),
        );
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_or_both_false() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::LogicalOr(
            Box::new(ConditionExpr::Never),
            Box::new(ConditionExpr::Never),
        );
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_not_true() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::Not(Box::new(ConditionExpr::Never));
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_not_false() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::Not(Box::new(ConditionExpr::Always));
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    // ── Condition evaluation: length ────────────────────────────────────

    #[test]
    fn pipeline_cond_eval_length_gt_true() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::LengthCheck {
            path: "steps.fetch.output.issues".to_owned(),
            op: CompareOp::Gt,
            value: 0,
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_length_eq_true() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::LengthCheck {
            path: "steps.fetch.output.issues".to_owned(),
            op: CompareOp::Eq,
            value: 2,
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_length_missing() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::LengthCheck {
            path: "steps.nope.output.x".to_owned(),
            op: CompareOp::Gt,
            value: 0,
        };
        assert!(evaluate_condition(&expr, &ctx).is_err());
    }

    // ── Condition evaluation: contains ──────────────────────────────────

    #[test]
    fn pipeline_cond_eval_contains_true() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::Contains {
            haystack: "steps.fetch.output.message".to_owned(),
            needle: "good".to_owned(),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_contains_false() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::Contains {
            haystack: "steps.fetch.output.message".to_owned(),
            needle: "bad".to_owned(),
        };
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_contains_array() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::Contains {
            haystack: "steps.fetch.output.tags".to_owned(),
            needle: "rust".to_owned(),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_contains_array_miss() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::Contains {
            haystack: "steps.fetch.output.tags".to_owned(),
            needle: "python".to_owned(),
        };
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    // ── Condition evaluation: always / never ────────────────────────────

    #[test]
    fn pipeline_cond_eval_always() {
        let ctx = PipelineContext::new();
        assert!(evaluate_condition(&ConditionExpr::Always, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_never() {
        let ctx = PipelineContext::new();
        assert!(!evaluate_condition(&ConditionExpr::Never, &ctx).unwrap());
    }

    // ── Error mode parsing ──────────────────────────────────────────────

    #[test]
    fn pipeline_cond_error_mode_skip() {
        assert_eq!(parse_error_mode("skip").unwrap(), ErrorMode::Skip);
    }

    #[test]
    fn pipeline_cond_error_mode_abort() {
        assert_eq!(parse_error_mode("abort").unwrap(), ErrorMode::Abort);
    }

    #[test]
    fn pipeline_cond_error_mode_retry() {
        assert_eq!(
            parse_error_mode("retry(3)").unwrap(),
            ErrorMode::Retry { max_attempts: 3 }
        );
    }

    #[test]
    fn pipeline_cond_error_mode_retry_zero() {
        assert!(parse_error_mode("retry(0)").is_err());
    }

    #[test]
    fn pipeline_cond_error_mode_fallback() {
        assert_eq!(
            parse_error_mode("fallback(cleanup)").unwrap(),
            ErrorMode::Fallback {
                step_id: "cleanup".to_owned(),
            }
        );
    }

    #[test]
    fn pipeline_cond_error_mode_fallback_empty() {
        assert!(parse_error_mode("fallback()").is_err());
    }

    #[test]
    fn pipeline_cond_error_mode_invalid() {
        assert!(parse_error_mode("explode").is_err());
    }

    #[test]
    fn pipeline_cond_error_mode_retry_bad_number() {
        assert!(parse_error_mode("retry(abc)").is_err());
    }

    // ── Error decision ──────────────────────────────────────────────────

    #[test]
    fn pipeline_cond_decision_skip() {
        let err = step_error("a", 1);
        assert_eq!(
            apply_error_mode(&ErrorMode::Skip, &err, 1),
            ErrorDecision::Skip
        );
    }

    #[test]
    fn pipeline_cond_decision_abort() {
        let err = step_error("a", 1);
        assert_eq!(
            apply_error_mode(&ErrorMode::Abort, &err, 1),
            ErrorDecision::Abort
        );
    }

    #[test]
    fn pipeline_cond_decision_retry_within_limit() {
        let err = step_error("a", 1);
        let mode = ErrorMode::Retry { max_attempts: 3 };
        assert_eq!(apply_error_mode(&mode, &err, 1), ErrorDecision::Retry);
    }

    #[test]
    fn pipeline_cond_decision_retry_at_limit() {
        let err = step_error("a", 3);
        let mode = ErrorMode::Retry { max_attempts: 3 };
        assert_eq!(apply_error_mode(&mode, &err, 3), ErrorDecision::Abort);
    }

    #[test]
    fn pipeline_cond_decision_fallback() {
        let err = step_error("a", 1);
        let mode = ErrorMode::Fallback {
            step_id: "recover".to_owned(),
        };
        assert_eq!(
            apply_error_mode(&mode, &err, 1),
            ErrorDecision::RunFallback("recover".to_owned())
        );
    }

    // ── PipelineContext ─────────────────────────────────────────────────

    #[test]
    fn pipeline_cond_context_set_get() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("step1", json!({"result": 42}));
        let v = ctx.get_output("step1").unwrap();
        assert_eq!(v, &json!({"result": 42}));
    }

    #[test]
    fn pipeline_cond_context_missing() {
        let ctx = PipelineContext::new();
        assert!(ctx.get_output("nope").is_none());
    }

    #[test]
    fn pipeline_cond_context_overwrite() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!(1));
        ctx.set_output("s", json!(2));
        assert_eq!(ctx.get_output("s").unwrap(), &json!(2));
    }

    // ── Template path resolution ────────────────────────────────────────

    #[test]
    fn pipeline_cond_resolve_simple() {
        let ctx = ctx_with_fetch();
        let v = resolve_template_path("steps.fetch.output.status", &ctx).unwrap();
        assert_eq!(v, json!("active"));
    }

    #[test]
    fn pipeline_cond_resolve_nested() {
        let ctx = ctx_with_fetch();
        let v = resolve_template_path("steps.fetch.output.issues[0].title", &ctx).unwrap();
        assert_eq!(v, json!("Bug A"));
    }

    #[test]
    fn pipeline_cond_resolve_array_index() {
        let ctx = ctx_with_fetch();
        let v = resolve_template_path("steps.fetch.output.issues[1].status", &ctx).unwrap();
        assert_eq!(v, json!("closed"));
    }

    #[test]
    fn pipeline_cond_resolve_missing_step() {
        let ctx = ctx_with_fetch();
        assert!(resolve_template_path("steps.nope.output.x", &ctx).is_none());
    }

    #[test]
    fn pipeline_cond_resolve_missing_field() {
        let ctx = ctx_with_fetch();
        assert!(resolve_template_path("steps.fetch.output.nonexistent", &ctx).is_none());
    }

    #[test]
    fn pipeline_cond_resolve_root_output() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!(99));
        let v = resolve_template_path("steps.s.output", &ctx).unwrap();
        assert_eq!(v, json!(99));
    }

    #[test]
    fn pipeline_cond_resolve_empty_path() {
        let ctx = PipelineContext::new();
        assert!(resolve_template_path("", &ctx).is_none());
    }

    #[test]
    fn pipeline_cond_resolve_array_out_of_bounds() {
        let ctx = ctx_with_fetch();
        assert!(resolve_template_path("steps.fetch.output.issues[99].title", &ctx).is_none());
    }

    // ── ExecutionTrace ──────────────────────────────────────────────────

    #[test]
    fn pipeline_cond_trace_construction() {
        let mut trace = ExecutionTrace::default();
        trace.steps.push(StepTraceEntry {
            step_id: "fetch".to_owned(),
            outcome: StepOutcome::Executed(json!({"ok": true})),
            condition_result: Some(true),
            error_mode: ErrorMode::Abort,
            duration_ms: 120,
            attempt: 1,
        });
        trace.steps.push(StepTraceEntry {
            step_id: "transform".to_owned(),
            outcome: StepOutcome::Skipped("condition false".to_owned()),
            condition_result: Some(false),
            error_mode: ErrorMode::Skip,
            duration_ms: 0,
            attempt: 1,
        });
        assert_eq!(trace.steps.len(), 2);
        assert_eq!(trace.steps[0].step_id, "fetch");
        assert_eq!(trace.steps[1].step_id, "transform");
    }

    #[test]
    fn pipeline_cond_trace_serialization() {
        let trace = ExecutionTrace {
            steps: vec![StepTraceEntry {
                step_id: "s1".to_owned(),
                outcome: StepOutcome::Executed(json!(42)),
                condition_result: None,
                error_mode: ErrorMode::Abort,
                duration_ms: 5,
                attempt: 1,
            }],
        };
        let json_str = serde_json::to_string(&trace).unwrap();
        assert!(json_str.contains("\"step_id\":\"s1\""));
        let roundtrip: ExecutionTrace = serde_json::from_str(&json_str).unwrap();
        assert_eq!(roundtrip.steps.len(), 1);
        assert_eq!(roundtrip.steps[0].step_id, "s1");
    }

    #[test]
    fn pipeline_cond_trace_failed_step() {
        let trace = ExecutionTrace {
            steps: vec![StepTraceEntry {
                step_id: "api_call".to_owned(),
                outcome: StepOutcome::Failed(StepError {
                    step_id: "api_call".to_owned(),
                    error_type: "http".to_owned(),
                    message: "503 Service Unavailable".to_owned(),
                    attempt: 2,
                }),
                condition_result: Some(true),
                error_mode: ErrorMode::Retry { max_attempts: 3 },
                duration_ms: 3000,
                attempt: 2,
            }],
        };
        let json_str = serde_json::to_string(&trace).unwrap();
        let roundtrip: ExecutionTrace = serde_json::from_str(&json_str).unwrap();
        match &roundtrip.steps[0].outcome {
            StepOutcome::Failed(e) => {
                assert_eq!(e.error_type, "http");
                assert_eq!(e.attempt, 2);
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // ── Combined: condition + error mode ────────────────────────────────

    #[test]
    fn pipeline_cond_combined_condition_and_error() {
        // Simulate: condition true → execute → fails → retry decision.
        let ctx = ctx_with_fetch();
        let cond = parse_condition("{{steps.fetch.output.count}} > 0").unwrap();
        let should_run = evaluate_condition(&cond.parsed, &ctx).unwrap();
        assert!(should_run);

        let mode = parse_error_mode("retry(2)").unwrap();
        let err = step_error("fetch", 1);
        let decision = apply_error_mode(&mode, &err, 1);
        assert_eq!(decision, ErrorDecision::Retry);

        // Second attempt also fails — should abort.
        let decision2 = apply_error_mode(&mode, &err, 2);
        assert_eq!(decision2, ErrorDecision::Abort);
    }

    #[test]
    fn pipeline_cond_combined_skip_on_condition_false() {
        // Condition false → step should be skipped, error mode irrelevant.
        let ctx = ctx_with_fetch();
        let cond = parse_condition("{{steps.fetch.output.count}} > 100").unwrap();
        let should_run = evaluate_condition(&cond.parsed, &ctx).unwrap();
        assert!(!should_run);

        let outcome = StepOutcome::Skipped("condition evaluated to false".to_owned());
        match &outcome {
            StepOutcome::Skipped(reason) => assert!(reason.contains("false")),
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    // ── Display impls ───────────────────────────────────────────────────

    #[test]
    fn pipeline_cond_compare_op_display() {
        assert_eq!(CompareOp::Eq.to_string(), "==");
        assert_eq!(CompareOp::Ne.to_string(), "!=");
        assert_eq!(CompareOp::Gt.to_string(), ">");
        assert_eq!(CompareOp::Gte.to_string(), ">=");
        assert_eq!(CompareOp::Lt.to_string(), "<");
        assert_eq!(CompareOp::Lte.to_string(), "<=");
    }

    #[test]
    fn pipeline_cond_value_display() {
        assert_eq!(ConditionValue::String("hi".to_owned()).to_string(), "'hi'");
        assert_eq!(ConditionValue::Number(3.5).to_string(), "3.5");
        assert_eq!(ConditionValue::Bool(true).to_string(), "true");
        assert_eq!(ConditionValue::Null.to_string(), "null");
    }

    #[test]
    fn pipeline_cond_step_error_display() {
        let e = step_error("deploy", 2);
        let s = e.to_string();
        assert!(s.contains("deploy"));
        assert!(s.contains("attempt 2"));
        assert!(s.contains("connection refused"));
    }

    #[test]
    fn pipeline_cond_parse_error_display() {
        assert_eq!(
            ConditionParseError::Empty.to_string(),
            "empty condition expression"
        );
        let e = ConditionParseError::InvalidSyntax("bad".to_owned());
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn pipeline_cond_eval_error_display() {
        let e = ConditionEvalError::MissingStep {
            path: "steps.x.output".to_owned(),
        };
        assert!(e.to_string().contains("steps.x.output"));
    }

    #[test]
    fn pipeline_cond_error_mode_parse_error_display() {
        let e = ErrorModeParseError {
            input: "boom".to_owned(),
            reason: "unrecognised".to_owned(),
        };
        assert!(e.to_string().contains("boom"));
    }

    // ── Default impls ───────────────────────────────────────────────────

    #[test]
    fn pipeline_cond_error_mode_default() {
        assert_eq!(ErrorMode::default(), ErrorMode::Abort);
    }

    #[test]
    fn pipeline_cond_context_default() {
        let ctx = PipelineContext::default();
        assert!(ctx.get_output("anything").is_none());
    }

    // ── Length on different types ────────────────────────────────────────

    #[test]
    fn pipeline_cond_length_string() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"text": "hello"}));
        let expr = ConditionExpr::LengthCheck {
            path: "steps.s.output.text".to_owned(),
            op: CompareOp::Eq,
            value: 5,
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_length_object() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"map": {"a": 1, "b": 2, "c": 3}}));
        let expr = ConditionExpr::LengthCheck {
            path: "steps.s.output.map".to_owned(),
            op: CompareOp::Eq,
            value: 3,
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    // ── split_path edge cases ─────────────────────────────────────────

    #[test]
    fn pipeline_cond_split_path_simple_dot() {
        let segs = split_path("a.b.c");
        assert_eq!(segs, vec!["a", "b", "c"]);
    }

    #[test]
    fn pipeline_cond_split_path_bracket_only() {
        let segs = split_path("[0]");
        assert_eq!(segs, vec!["0"]);
    }

    #[test]
    fn pipeline_cond_split_path_multiple_brackets() {
        let segs = split_path("data[0][1]");
        assert_eq!(segs, vec!["data", "0", "1"]);
    }

    #[test]
    fn pipeline_cond_split_path_nested_dot_bracket() {
        let segs = split_path("steps.fetch.output.items[2].name");
        assert_eq!(segs, vec!["steps", "fetch", "output", "items", "2", "name"]);
    }

    #[test]
    fn pipeline_cond_split_path_single_segment() {
        let segs = split_path("root");
        assert_eq!(segs, vec!["root"]);
    }

    #[test]
    fn pipeline_cond_split_path_empty() {
        let segs = split_path("");
        assert_eq!(segs, vec![""]);
    }

    // ── resolve_template_path: short-form paths ───────────────────────

    #[test]
    fn pipeline_cond_resolve_short_form() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("fetch", json!({"result": "ok"}));
        let v = resolve_template_path("fetch.output.result", &ctx).unwrap();
        assert_eq!(v, json!("ok"));
    }

    #[test]
    fn pipeline_cond_resolve_short_form_root() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!(42));
        let v = resolve_template_path("s.output", &ctx).unwrap();
        assert_eq!(v, json!(42));
    }

    #[test]
    fn pipeline_cond_resolve_steps_too_short() {
        let ctx = ctx_with_fetch();
        // "steps.fetch" is only 2 segments (need at least 3 when starts with "steps")
        assert!(resolve_template_path("steps.fetch", &ctx).is_none());
    }

    #[test]
    fn pipeline_cond_resolve_single_segment() {
        let ctx = ctx_with_fetch();
        // Single segment without "output" as second
        assert!(resolve_template_path("fetch", &ctx).is_none());
    }

    #[test]
    fn pipeline_cond_resolve_steps_prefix_only() {
        let ctx = ctx_with_fetch();
        assert!(resolve_template_path("steps", &ctx).is_none());
    }

    #[test]
    fn pipeline_cond_resolve_deep_nested() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"a": {"b": {"c": {"d": 99}}}}));
        let v = resolve_template_path("steps.s.output.a.b.c.d", &ctx).unwrap();
        assert_eq!(v, json!(99));
    }

    #[test]
    fn pipeline_cond_resolve_array_then_field() {
        let ctx = ctx_with_fetch();
        let v = resolve_template_path("steps.fetch.output.issues[1].title", &ctx).unwrap();
        assert_eq!(v, json!("Bug B"));
    }

    // ── is_truthy coverage ────────────────────────────────────────────

    #[test]
    fn pipeline_cond_eval_truthy_number_zero() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": 0}));
        let expr = ConditionExpr::Truthy("steps.s.output.val".to_owned());
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_truthy_number_nonzero() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": 42}));
        let expr = ConditionExpr::Truthy("steps.s.output.val".to_owned());
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_truthy_empty_string() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": ""}));
        let expr = ConditionExpr::Truthy("steps.s.output.val".to_owned());
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_truthy_nonempty_string() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": "hi"}));
        let expr = ConditionExpr::Truthy("steps.s.output.val".to_owned());
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_truthy_empty_array() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": []}));
        let expr = ConditionExpr::Truthy("steps.s.output.val".to_owned());
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_truthy_nonempty_array() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": [1]}));
        let expr = ConditionExpr::Truthy("steps.s.output.val".to_owned());
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_truthy_empty_object() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": {}}));
        let expr = ConditionExpr::Truthy("steps.s.output.val".to_owned());
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_truthy_nonempty_object() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": {"k": "v"}}));
        let expr = ConditionExpr::Truthy("steps.s.output.val".to_owned());
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_eval_truthy_bool_false() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": false}));
        let expr = ConditionExpr::Truthy("steps.s.output.val".to_owned());
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    // ── compare_value: type mismatches ────────────────────────────────

    #[test]
    fn pipeline_cond_compare_string_vs_number_returns_false() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": "hello"}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Eq,
            right: ConditionValue::Number(5.0),
        };
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_compare_number_vs_bool_returns_false() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": 1}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Eq,
            right: ConditionValue::Bool(true),
        };
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_compare_bool_ne() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"flag": true}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.flag".to_owned(),
            op: CompareOp::Ne,
            right: ConditionValue::Bool(false),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_compare_bool_gt_returns_false() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"flag": true}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.flag".to_owned(),
            op: CompareOp::Gt,
            right: ConditionValue::Bool(false),
        };
        // Gt on booleans is not meaningful, returns false
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_compare_null_ne() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": "something"}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Ne,
            right: ConditionValue::Null,
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_compare_null_gt_returns_false() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": null}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Gt,
            right: ConditionValue::Null,
        };
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    // ── compare_value: string ordering ────────────────────────────────

    #[test]
    fn pipeline_cond_compare_string_gt() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": "banana"}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Gt,
            right: ConditionValue::String("apple".to_owned()),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_compare_string_lt() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": "apple"}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Lt,
            right: ConditionValue::String("banana".to_owned()),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_compare_string_gte_equal() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": "same"}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Gte,
            right: ConditionValue::String("same".to_owned()),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_compare_string_lte_equal() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": "same"}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Lte,
            right: ConditionValue::String("same".to_owned()),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    // ── compare_value: number operators ───────────────────────────────

    #[test]
    fn pipeline_cond_compare_number_ne() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": 10}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Ne,
            right: ConditionValue::Number(5.0),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_compare_number_lt() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": 3}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Lt,
            right: ConditionValue::Number(5.0),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_compare_number_gte_equal() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": 5}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Gte,
            right: ConditionValue::Number(5.0),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_compare_number_lte_strict() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": 4}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Lte,
            right: ConditionValue::Number(5.0),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_compare_number_eq_exact() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": 2.5}));
        let expr = ConditionExpr::Comparison {
            left: "steps.s.output.val".to_owned(),
            op: CompareOp::Eq,
            right: ConditionValue::Number(2.5),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    // ── value_length: non-container types ─────────────────────────────

    #[test]
    fn pipeline_cond_length_of_number_is_zero() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": 42}));
        let expr = ConditionExpr::LengthCheck {
            path: "steps.s.output.val".to_owned(),
            op: CompareOp::Eq,
            value: 0,
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_length_of_bool_is_zero() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": true}));
        let expr = ConditionExpr::LengthCheck {
            path: "steps.s.output.val".to_owned(),
            op: CompareOp::Eq,
            value: 0,
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_length_of_null_is_zero() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": null}));
        let expr = ConditionExpr::LengthCheck {
            path: "steps.s.output.val".to_owned(),
            op: CompareOp::Eq,
            value: 0,
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_length_ne() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::LengthCheck {
            path: "steps.fetch.output.issues".to_owned(),
            op: CompareOp::Ne,
            value: 5,
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_length_lt() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::LengthCheck {
            path: "steps.fetch.output.issues".to_owned(),
            op: CompareOp::Lt,
            value: 10,
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_length_gte() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::LengthCheck {
            path: "steps.fetch.output.issues".to_owned(),
            op: CompareOp::Gte,
            value: 2,
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_length_lte() {
        let ctx = ctx_with_fetch();
        let expr = ConditionExpr::LengthCheck {
            path: "steps.fetch.output.issues".to_owned(),
            op: CompareOp::Lte,
            value: 2,
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    // ── value_contains: edge cases ────────────────────────────────────

    #[test]
    fn pipeline_cond_contains_on_number_is_false() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"val": 42}));
        let expr = ConditionExpr::Contains {
            haystack: "steps.s.output.val".to_owned(),
            needle: "42".to_owned(),
        };
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_contains_missing_step() {
        let ctx = PipelineContext::new();
        let expr = ConditionExpr::Contains {
            haystack: "steps.nope.output.text".to_owned(),
            needle: "x".to_owned(),
        };
        assert!(evaluate_condition(&expr, &ctx).is_err());
    }

    #[test]
    fn pipeline_cond_contains_empty_needle() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"text": "hello world"}));
        let expr = ConditionExpr::Contains {
            haystack: "steps.s.output.text".to_owned(),
            needle: String::new(),
        };
        // empty string is always contained
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_contains_array_with_non_string_elements() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"arr": [1, 2, "three"]}));
        let expr = ConditionExpr::Contains {
            haystack: "steps.s.output.arr".to_owned(),
            needle: "three".to_owned(),
        };
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_contains_array_non_string_miss() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"arr": [1, 2, 3]}));
        let expr = ConditionExpr::Contains {
            haystack: "steps.s.output.arr".to_owned(),
            needle: "1".to_owned(),
        };
        // numbers in array don't match string needle
        assert!(!evaluate_condition(&expr, &ctx).unwrap());
    }

    // ── Condition parsing: case-insensitive always/never ──────────────

    #[test]
    fn pipeline_cond_parse_always_upper() {
        let c = parse_condition("ALWAYS").unwrap();
        assert_eq!(c.parsed, ConditionExpr::Always);
    }

    #[test]
    fn pipeline_cond_parse_never_mixed_case() {
        let c = parse_condition("Never").unwrap();
        assert_eq!(c.parsed, ConditionExpr::Never);
    }

    // ── Condition parsing: double-quoted string comparison ────────────

    #[test]
    fn pipeline_cond_parse_comparison_double_quoted() {
        let c = parse_condition("{{steps.a.output.x}} == \"hello\"").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Comparison {
                left: "steps.a.output.x".to_owned(),
                op: CompareOp::Eq,
                right: ConditionValue::String("hello".to_owned()),
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_comparison_bool_false() {
        let c = parse_condition("{{steps.x.output.flag}} == false").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Comparison {
                left: "steps.x.output.flag".to_owned(),
                op: CompareOp::Eq,
                right: ConditionValue::Bool(false),
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_comparison_negative_number() {
        let c = parse_condition("{{steps.x.output.val}} > -1").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Comparison {
                left: "steps.x.output.val".to_owned(),
                op: CompareOp::Gt,
                right: ConditionValue::Number(-1.0),
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_comparison_float() {
        let c = parse_condition("{{steps.x.output.val}} == 2.5").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::Comparison {
                left: "steps.x.output.val".to_owned(),
                op: CompareOp::Eq,
                right: ConditionValue::Number(2.5),
            }
        );
    }

    // ── Condition parsing: complex logical expressions ────────────────

    #[test]
    fn pipeline_cond_parse_nested_not_and() {
        let c = parse_condition("!{{steps.a.output.skip}} && {{steps.b.output.ready}} == true")
            .unwrap();
        match &c.parsed {
            ConditionExpr::LogicalAnd(l, r) => {
                assert!(matches!(l.as_ref(), ConditionExpr::Not(_)));
                assert!(matches!(r.as_ref(), ConditionExpr::Comparison { .. }));
            }
            other => panic!("expected LogicalAnd, got {other:?}"),
        }
    }

    #[test]
    fn pipeline_cond_parse_or_then_and() {
        // OR has lower precedence than AND
        let c = parse_condition(
            "{{steps.a.output.x}} == 'yes' || {{steps.b.output.y}} == 'yes' && {{steps.c.output.z}} == 'yes'",
        )
        .unwrap();
        // Should be OR(comparison, AND(comparison, comparison))
        assert!(matches!(c.parsed, ConditionExpr::LogicalOr(_, _)));
    }

    #[test]
    fn pipeline_cond_parse_double_not() {
        let c = parse_condition("!!{{steps.a.output.x}}").unwrap();
        match &c.parsed {
            ConditionExpr::Not(inner) => {
                assert!(matches!(inner.as_ref(), ConditionExpr::Not(_)));
            }
            other => panic!("expected Not(Not(...)), got {other:?}"),
        }
    }

    // ── Condition parsing: invalid expressions ────────────────────────

    #[test]
    fn pipeline_cond_parse_empty_template() {
        let err = parse_condition("{{}}").unwrap_err();
        assert!(matches!(err, ConditionParseError::InvalidSyntax(_)));
    }

    #[test]
    fn pipeline_cond_parse_bad_contains_needle() {
        let err = parse_condition("{{steps.a.output.x}} contains unquoted").unwrap_err();
        assert!(matches!(err, ConditionParseError::InvalidSyntax(_)));
    }

    #[test]
    fn pipeline_cond_parse_bad_length_value() {
        let err = parse_condition("{{steps.a.output.x | length}} > abc").unwrap_err();
        assert!(matches!(err, ConditionParseError::InvalidSyntax(_)));
    }

    #[test]
    fn pipeline_cond_parse_bad_operator() {
        let err = parse_condition("{{steps.a.output.x}} ~= 5").unwrap_err();
        assert!(matches!(err, ConditionParseError::InvalidSyntax(_)));
    }

    // ── Condition parsing: length with all operators ──────────────────

    #[test]
    fn pipeline_cond_parse_length_ne() {
        let c = parse_condition("{{steps.a.output.items | length}} != 0").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::LengthCheck {
                path: "steps.a.output.items".to_owned(),
                op: CompareOp::Ne,
                value: 0,
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_length_lt() {
        let c = parse_condition("{{steps.a.output.items | length}} < 100").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::LengthCheck {
                path: "steps.a.output.items".to_owned(),
                op: CompareOp::Lt,
                value: 100,
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_length_gte() {
        let c = parse_condition("{{steps.a.output.items | length}} >= 1").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::LengthCheck {
                path: "steps.a.output.items".to_owned(),
                op: CompareOp::Gte,
                value: 1,
            }
        );
    }

    #[test]
    fn pipeline_cond_parse_length_lte() {
        let c = parse_condition("{{steps.a.output.items | length}} <= 50").unwrap();
        assert_eq!(
            c.parsed,
            ConditionExpr::LengthCheck {
                path: "steps.a.output.items".to_owned(),
                op: CompareOp::Lte,
                value: 50,
            }
        );
    }

    // ── Error mode parsing: whitespace / boundary ─────────────────────

    #[test]
    fn pipeline_cond_error_mode_skip_with_whitespace() {
        assert_eq!(parse_error_mode("  skip  ").unwrap(), ErrorMode::Skip);
    }

    #[test]
    fn pipeline_cond_error_mode_retry_one() {
        assert_eq!(
            parse_error_mode("retry(1)").unwrap(),
            ErrorMode::Retry { max_attempts: 1 }
        );
    }

    #[test]
    fn pipeline_cond_error_mode_fallback_with_whitespace_id() {
        assert_eq!(
            parse_error_mode("fallback( cleanup_step )").unwrap(),
            ErrorMode::Fallback {
                step_id: "cleanup_step".to_owned(),
            }
        );
    }

    // ── Error decision: boundary conditions ───────────────────────────

    #[test]
    fn pipeline_cond_decision_retry_just_under_limit() {
        let err = step_error("a", 2);
        let mode = ErrorMode::Retry { max_attempts: 3 };
        assert_eq!(apply_error_mode(&mode, &err, 2), ErrorDecision::Retry);
    }

    #[test]
    fn pipeline_cond_decision_retry_over_limit() {
        let err = step_error("a", 5);
        let mode = ErrorMode::Retry { max_attempts: 3 };
        assert_eq!(apply_error_mode(&mode, &err, 5), ErrorDecision::Abort);
    }

    #[test]
    fn pipeline_cond_decision_retry_at_one() {
        let err = step_error("a", 1);
        let mode = ErrorMode::Retry { max_attempts: 1 };
        // attempt == max_attempts, should abort
        assert_eq!(apply_error_mode(&mode, &err, 1), ErrorDecision::Abort);
    }

    // ── Serde roundtrips ──────────────────────────────────────────────

    #[test]
    fn pipeline_cond_serde_condition_value_variants() {
        let values = vec![
            ConditionValue::String("test".to_owned()),
            ConditionValue::Number(42.5),
            ConditionValue::Bool(true),
            ConditionValue::Null,
        ];
        for v in &values {
            let json = serde_json::to_string(v).unwrap();
            let back: ConditionValue = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn pipeline_cond_serde_condition_expr_truthy() {
        let expr = ConditionExpr::Truthy("steps.a.output.x".to_owned());
        let json = serde_json::to_string(&expr).unwrap();
        let back: ConditionExpr = serde_json::from_str(&json).unwrap();
        assert_eq!(back, expr);
    }

    #[test]
    fn pipeline_cond_serde_condition_expr_comparison() {
        let expr = ConditionExpr::Comparison {
            left: "steps.a.output.x".to_owned(),
            op: CompareOp::Gte,
            right: ConditionValue::Number(10.0),
        };
        let json = serde_json::to_string(&expr).unwrap();
        let back: ConditionExpr = serde_json::from_str(&json).unwrap();
        assert_eq!(back, expr);
    }

    #[test]
    fn pipeline_cond_serde_condition_expr_logical() {
        let expr = ConditionExpr::LogicalAnd(
            Box::new(ConditionExpr::Always),
            Box::new(ConditionExpr::Not(Box::new(ConditionExpr::Never))),
        );
        let json = serde_json::to_string(&expr).unwrap();
        let back: ConditionExpr = serde_json::from_str(&json).unwrap();
        assert_eq!(back, expr);
    }

    #[test]
    fn pipeline_cond_serde_condition_expr_length_check() {
        let expr = ConditionExpr::LengthCheck {
            path: "steps.a.output.items".to_owned(),
            op: CompareOp::Lt,
            value: 50,
        };
        let json = serde_json::to_string(&expr).unwrap();
        let back: ConditionExpr = serde_json::from_str(&json).unwrap();
        assert_eq!(back, expr);
    }

    #[test]
    fn pipeline_cond_serde_condition_expr_contains() {
        let expr = ConditionExpr::Contains {
            haystack: "steps.a.output.text".to_owned(),
            needle: "hello".to_owned(),
        };
        let json = serde_json::to_string(&expr).unwrap();
        let back: ConditionExpr = serde_json::from_str(&json).unwrap();
        assert_eq!(back, expr);
    }

    #[test]
    fn pipeline_cond_serde_condition_struct() {
        let c = Condition {
            raw: "always".to_owned(),
            parsed: ConditionExpr::Always,
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: Condition = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn pipeline_cond_serde_error_mode_all_variants() {
        let modes = vec![
            ErrorMode::Skip,
            ErrorMode::Abort,
            ErrorMode::Retry { max_attempts: 5 },
            ErrorMode::Fallback {
                step_id: "backup".to_owned(),
            },
        ];
        for m in &modes {
            let json = serde_json::to_string(m).unwrap();
            let back: ErrorMode = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, m);
        }
    }

    #[test]
    fn pipeline_cond_serde_step_outcome_all_variants() {
        let outcomes = vec![
            StepOutcome::Executed(json!({"ok": true})),
            StepOutcome::Skipped("no reason".to_owned()),
            StepOutcome::Failed(StepError {
                step_id: "x".to_owned(),
                error_type: "io".to_owned(),
                message: "timeout".to_owned(),
                attempt: 3,
            }),
        ];
        for o in &outcomes {
            let json = serde_json::to_string(o).unwrap();
            let _back: StepOutcome = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn pipeline_cond_serde_step_error() {
        let e = StepError {
            step_id: "deploy".to_owned(),
            error_type: "auth".to_owned(),
            message: "token expired".to_owned(),
            attempt: 1,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: StepError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.step_id, "deploy");
        assert_eq!(back.error_type, "auth");
        assert_eq!(back.message, "token expired");
        assert_eq!(back.attempt, 1);
    }

    // ── Clone impls ───────────────────────────────────────────────────

    #[test]
    fn pipeline_cond_clone_compare_op() {
        let op = CompareOp::Gte;
        let cloned = op.clone();
        assert_eq!(op, cloned);
    }

    #[test]
    fn pipeline_cond_clone_condition_expr() {
        let expr = ConditionExpr::LogicalOr(
            Box::new(ConditionExpr::Always),
            Box::new(ConditionExpr::Never),
        );
        let cloned = expr.clone();
        assert_eq!(expr, cloned);
    }

    #[test]
    fn pipeline_cond_clone_condition() {
        let c = parse_condition("always").unwrap();
        let cloned = c.clone();
        assert_eq!(c, cloned);
    }

    #[test]
    fn pipeline_cond_clone_error_mode() {
        let m = ErrorMode::Retry { max_attempts: 3 };
        let cloned = m.clone();
        assert_eq!(m, cloned);
    }

    #[test]
    fn pipeline_cond_clone_pipeline_context() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s1", json!(42));
        let cloned = ctx.clone();
        assert_eq!(cloned.get_output("s1").unwrap(), &json!(42));
    }

    // ── ExecutionTrace: additional coverage ───────────────────────────

    #[test]
    fn pipeline_cond_trace_empty() {
        let trace = ExecutionTrace::default();
        assert!(trace.steps.is_empty());
    }

    #[test]
    fn pipeline_cond_trace_multiple_entries_roundtrip() {
        let trace = ExecutionTrace {
            steps: vec![
                StepTraceEntry {
                    step_id: "s1".to_owned(),
                    outcome: StepOutcome::Executed(json!("ok")),
                    condition_result: Some(true),
                    error_mode: ErrorMode::Abort,
                    duration_ms: 10,
                    attempt: 1,
                },
                StepTraceEntry {
                    step_id: "s2".to_owned(),
                    outcome: StepOutcome::Skipped("cond false".to_owned()),
                    condition_result: Some(false),
                    error_mode: ErrorMode::Skip,
                    duration_ms: 0,
                    attempt: 1,
                },
                StepTraceEntry {
                    step_id: "s3".to_owned(),
                    outcome: StepOutcome::Failed(StepError {
                        step_id: "s3".to_owned(),
                        error_type: "net".to_owned(),
                        message: "dns failed".to_owned(),
                        attempt: 1,
                    }),
                    condition_result: Some(true),
                    error_mode: ErrorMode::Fallback {
                        step_id: "s4".to_owned(),
                    },
                    duration_ms: 5000,
                    attempt: 1,
                },
            ],
        };
        let json_str = serde_json::to_string(&trace).unwrap();
        let roundtrip: ExecutionTrace = serde_json::from_str(&json_str).unwrap();
        assert_eq!(roundtrip.steps.len(), 3);
        assert_eq!(roundtrip.steps[2].step_id, "s3");
    }

    // ── Combined: full pipeline simulation ────────────────────────────

    #[test]
    fn pipeline_cond_combined_full_pipeline_sim() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("fetch", json!({"items": ["a", "b", "c"], "count": 3}));

        // Step 1: check length
        let c1 = parse_condition("{{steps.fetch.output.items | length}} > 0").unwrap();
        assert!(evaluate_condition(&c1.parsed, &ctx).unwrap());

        // Step 2: check contains
        let c2 = parse_condition("{{steps.fetch.output.items}} contains 'b'").unwrap();
        assert!(evaluate_condition(&c2.parsed, &ctx).unwrap());

        // Step 3: check count
        let c3 = parse_condition("{{steps.fetch.output.count}} == 3").unwrap();
        assert!(evaluate_condition(&c3.parsed, &ctx).unwrap());

        // Record step outputs in trace
        let mut trace = ExecutionTrace::default();
        trace.steps.push(StepTraceEntry {
            step_id: "length_check".to_owned(),
            outcome: StepOutcome::Executed(json!(true)),
            condition_result: Some(true),
            error_mode: ErrorMode::Abort,
            duration_ms: 1,
            attempt: 1,
        });
        assert_eq!(trace.steps.len(), 1);
    }

    #[test]
    fn pipeline_cond_combined_or_with_missing_and_present() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("a", json!({"val": false}));
        ctx.set_output("b", json!({"val": true}));

        let expr = ConditionExpr::LogicalOr(
            Box::new(ConditionExpr::Truthy("steps.a.output.val".to_owned())),
            Box::new(ConditionExpr::Truthy("steps.b.output.val".to_owned())),
        );
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    #[test]
    fn pipeline_cond_combined_and_with_both_comparisons() {
        let mut ctx = PipelineContext::new();
        ctx.set_output("s", json!({"x": 10, "y": "active"}));

        let expr = ConditionExpr::LogicalAnd(
            Box::new(ConditionExpr::Comparison {
                left: "steps.s.output.x".to_owned(),
                op: CompareOp::Gte,
                right: ConditionValue::Number(5.0),
            }),
            Box::new(ConditionExpr::Comparison {
                left: "steps.s.output.y".to_owned(),
                op: CompareOp::Eq,
                right: ConditionValue::String("active".to_owned()),
            }),
        );
        assert!(evaluate_condition(&expr, &ctx).unwrap());
    }

    // ── Error type trait impls ────────────────────────────────────────

    #[test]
    fn pipeline_cond_condition_parse_error_is_std_error() {
        let e: Box<dyn std::error::Error> =
            Box::new(ConditionParseError::InvalidSyntax("oops".to_owned()));
        assert!(e.to_string().contains("oops"));
    }

    #[test]
    fn pipeline_cond_condition_eval_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(ConditionEvalError::MissingStep {
            path: "steps.x.output".to_owned(),
        });
        assert!(e.to_string().contains("steps.x.output"));
    }

    #[test]
    fn pipeline_cond_error_mode_parse_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(ErrorModeParseError {
            input: "bad".to_owned(),
            reason: "nope".to_owned(),
        });
        assert!(e.to_string().contains("bad"));
    }

    // ── ConditionValue Display: additional ────────────────────────────

    #[test]
    fn pipeline_cond_value_display_bool_false() {
        assert_eq!(ConditionValue::Bool(false).to_string(), "false");
    }

    #[test]
    fn pipeline_cond_value_display_negative_number() {
        assert_eq!(ConditionValue::Number(-2.5).to_string(), "-2.5");
    }

    #[test]
    fn pipeline_cond_value_display_zero() {
        assert_eq!(ConditionValue::Number(0.0).to_string(), "0");
    }

    #[test]
    fn pipeline_cond_value_display_empty_string() {
        assert_eq!(ConditionValue::String(String::new()).to_string(), "''");
    }
}
