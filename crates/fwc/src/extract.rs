//! jq-style field extraction engine for `--extract` flag post-processing.
//!
//! Implements a lightweight subset of jq syntax without external jq dependencies.
//! Supported syntax:
//! - `.field` — object field access
//! - `.field.nested` — nested field access
//! - `.[0]` — array index
//! - `.[]` — iterate array
//! - `.field[0].nested` — chained access
//! - `| length` — pipe to length function
//! - `{field1, field2}` — object construction (select fields)
//! - `.field // default` — alternative operator (default if null)

use serde_json::Value;
use std::fmt;

// ── Types ───────────────────────────────────────────────────────────────

/// A parsed extraction expression.
#[derive(Clone, Debug, PartialEq)]
pub enum ExtractExpr {
    /// Identity: `.`
    Identity,
    /// Field access: `.field`
    Field(String),
    /// Nested chain: `.field.nested[0]`
    Chain(Vec<ChainSegment>),
    /// Array iteration: `.[]` or `.field[]`
    Iterate(Box<ExtractExpr>),
    /// Pipe to function: `<expr> | <func>`
    Pipe(Box<ExtractExpr>, PipeFunc),
    /// Object construction: `{field1, field2}`
    ObjectConstruct(Vec<String>),
    /// Alternative operator: `<expr> // <default>`
    Alternative(Box<ExtractExpr>, Value),
}

/// A segment in a chain expression.
#[derive(Clone, Debug, PartialEq)]
pub enum ChainSegment {
    /// `.field`
    Field(String),
    /// `.[n]`
    Index(usize),
    /// `.[]`
    IterArray,
}

/// Built-in pipe functions.
#[derive(Clone, Debug, PartialEq)]
pub enum PipeFunc {
    Length,
    Keys,
    Values,
    Type,
    Not,
    Flatten,
    Reverse,
    Min,
    Max,
    Unique,
    Sort,
    First,
    Last,
    Empty,
    Ascii,
    AsciiDowncase,
    AsciiUpcase,
    Tostring,
    Tonumber,
    Ltrimstr(String),
    Rtrimstr(String),
    Add,
    Any,
    All,
}

/// Result of extraction.
#[derive(Clone, Debug, PartialEq)]
pub enum ExtractResult {
    /// A single JSON value.
    Single(Value),
    /// Multiple values (from array iteration).
    Multiple(Vec<Value>),
    /// Null / missing.
    Null,
}

impl ExtractResult {
    /// Convert to a single `Value`.
    pub fn into_value(self) -> Value {
        match self {
            Self::Single(v) => v,
            Self::Multiple(vs) => Value::Array(vs),
            Self::Null => Value::Null,
        }
    }
}

/// Extraction errors.
#[derive(Clone, Debug, PartialEq)]
pub enum ExtractError {
    /// The expression could not be parsed.
    ParseError(String),
    /// A type mismatch during evaluation (e.g. field access on non-object).
    TypeError(String),
    /// Index out of bounds.
    IndexOutOfBounds { index: usize, len: usize },
    /// Unknown pipe function.
    UnknownFunction(String),
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseError(msg) => write!(f, "parse error: {msg}"),
            Self::TypeError(msg) => write!(f, "type error: {msg}"),
            Self::IndexOutOfBounds { index, len } => {
                write!(f, "index {index} out of bounds (length {len})")
            }
            Self::UnknownFunction(name) => write!(f, "unknown function: {name}"),
        }
    }
}

impl std::error::Error for ExtractError {}

// ── Parsing ─────────────────────────────────────────────────────────────

/// Parse a jq-style extraction expression.
pub fn parse_extract(expr: &str) -> Result<ExtractExpr, ExtractError> {
    let expr = expr.trim();
    if expr.is_empty() {
        return Err(ExtractError::ParseError("empty expression".into()));
    }

    // Check for alternative operator first (top-level split on ` // `)
    if let Some((left, right)) = split_alternative(expr) {
        let left_expr = parse_extract(left.trim())?;
        let default_val = parse_default_value(right.trim())?;
        return Ok(ExtractExpr::Alternative(Box::new(left_expr), default_val));
    }

    // Check for pipe operator (top-level split on ` | `)
    if let Some((left, right)) = split_pipe(expr) {
        let left_expr = parse_extract(left.trim())?;
        let func = parse_pipe_func(right.trim())?;
        return Ok(ExtractExpr::Pipe(Box::new(left_expr), func));
    }

    // Object construction: {field1, field2}
    if expr.starts_with('{') && expr.ends_with('}') {
        let inner = &expr[1..expr.len() - 1];
        let fields: Vec<String> = inner
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if fields.is_empty() {
            return Err(ExtractError::ParseError("empty object construction".into()));
        }
        return Ok(ExtractExpr::ObjectConstruct(fields));
    }

    // Identity
    if expr == "." {
        return Ok(ExtractExpr::Identity);
    }

    // Must start with `.`
    if !expr.starts_with('.') {
        return Err(ExtractError::ParseError(format!(
            "expression must start with '.', got: {expr}"
        )));
    }

    // Parse chain of segments
    let segments = parse_chain(&expr[1..])?;

    // Check if last segment is IterArray — if so, wrap in Iterate
    if segments.last() == Some(&ChainSegment::IterArray) {
        let mut inner = segments;
        inner.pop();
        let base = if inner.is_empty() {
            ExtractExpr::Identity
        } else if inner.len() == 1 {
            match &inner[0] {
                ChainSegment::Field(f) => ExtractExpr::Field(f.clone()),
                _ => ExtractExpr::Chain(inner),
            }
        } else {
            ExtractExpr::Chain(inner)
        };
        return Ok(ExtractExpr::Iterate(Box::new(base)));
    }

    // Single field
    if segments.len() == 1 {
        if let ChainSegment::Field(f) = &segments[0] {
            return Ok(ExtractExpr::Field(f.clone()));
        }
    }

    Ok(ExtractExpr::Chain(segments))
}

/// Split on top-level ` // ` (alternative operator).
fn split_alternative(expr: &str) -> Option<(&str, &str)> {
    // Find ` // ` not inside brackets or braces
    let bytes = expr.as_bytes();
    let mut depth_bracket = 0i32;
    let mut depth_brace = 0i32;
    let mut i = 0;
    while i + 3 < bytes.len() {
        match bytes[i] {
            b'[' => depth_bracket += 1,
            b']' => depth_bracket -= 1,
            b'{' => depth_brace += 1,
            b'}' => depth_brace -= 1,
            b' ' if depth_bracket == 0
                && depth_brace == 0
                && i + 3 < bytes.len()
                && bytes[i + 1] == b'/'
                && bytes[i + 2] == b'/'
                && bytes[i + 3] == b' ' =>
            {
                return Some((&expr[..i], &expr[i + 4..]));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Split on top-level ` | ` (pipe operator).
fn split_pipe(expr: &str) -> Option<(&str, &str)> {
    let bytes = expr.as_bytes();
    let mut depth_bracket = 0i32;
    let mut depth_brace = 0i32;
    let mut i = 0;
    while i + 2 < bytes.len() {
        match bytes[i] {
            b'[' => depth_bracket += 1,
            b']' => depth_bracket -= 1,
            b'{' => depth_brace += 1,
            b'}' => depth_brace -= 1,
            b' ' if depth_bracket == 0
                && depth_brace == 0
                && bytes[i + 1] == b'|'
                && bytes[i + 2] == b' ' =>
            {
                return Some((&expr[..i], &expr[i + 3..]));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Parse a chain of segments from the part after the leading `.`.
fn parse_chain(s: &str) -> Result<Vec<ChainSegment>, ExtractError> {
    if s.is_empty() {
        return Ok(vec![]);
    }
    let mut segments = Vec::new();
    let mut remaining = s;

    while !remaining.is_empty() {
        // Array index or iteration: [N] or []
        if remaining.starts_with('[') {
            if let Some(close) = remaining.find(']') {
                let inner = &remaining[1..close];
                if inner.is_empty() {
                    segments.push(ChainSegment::IterArray);
                } else {
                    let idx: usize = inner.parse().map_err(|_| {
                        ExtractError::ParseError(format!("invalid array index: {inner}"))
                    })?;
                    segments.push(ChainSegment::Index(idx));
                }
                remaining = &remaining[close + 1..];
                // Skip trailing dot
                if remaining.starts_with('.') {
                    remaining = &remaining[1..];
                }
            } else {
                return Err(ExtractError::ParseError(
                    "unclosed bracket in expression".into(),
                ));
            }
        } else {
            // Field name — read until `.` or `[`
            let end = remaining.find(['.', '[']).unwrap_or(remaining.len());
            let field = &remaining[..end];
            if field.is_empty() {
                return Err(ExtractError::ParseError("empty field name in chain".into()));
            }
            segments.push(ChainSegment::Field(field.to_string()));
            remaining = &remaining[end..];
            // Skip the `.` separator
            if remaining.starts_with('.') {
                remaining = &remaining[1..];
            }
        }
    }

    if segments.is_empty() {
        return Err(ExtractError::ParseError("empty chain expression".into()));
    }
    Ok(segments)
}

/// Parse a pipe function name.
fn parse_pipe_func(name: &str) -> Result<PipeFunc, ExtractError> {
    match name {
        "length" => Ok(PipeFunc::Length),
        "keys" => Ok(PipeFunc::Keys),
        "values" => Ok(PipeFunc::Values),
        "type" => Ok(PipeFunc::Type),
        "not" => Ok(PipeFunc::Not),
        "flatten" => Ok(PipeFunc::Flatten),
        "reverse" => Ok(PipeFunc::Reverse),
        "min" => Ok(PipeFunc::Min),
        "max" => Ok(PipeFunc::Max),
        "unique" => Ok(PipeFunc::Unique),
        "sort" => Ok(PipeFunc::Sort),
        "first" => Ok(PipeFunc::First),
        "last" => Ok(PipeFunc::Last),
        "empty" => Ok(PipeFunc::Empty),
        "ascii" => Ok(PipeFunc::Ascii),
        "ascii_downcase" => Ok(PipeFunc::AsciiDowncase),
        "ascii_upcase" => Ok(PipeFunc::AsciiUpcase),
        "tostring" => Ok(PipeFunc::Tostring),
        "tonumber" => Ok(PipeFunc::Tonumber),
        "add" => Ok(PipeFunc::Add),
        "any" => Ok(PipeFunc::Any),
        "all" => Ok(PipeFunc::All),
        _ if name.starts_with("ltrimstr(") && name.ends_with(')') => {
            let inner = &name[9..name.len() - 1];
            let s = inner.trim_matches('"');
            Ok(PipeFunc::Ltrimstr(s.to_string()))
        }
        _ if name.starts_with("rtrimstr(") && name.ends_with(')') => {
            let inner = &name[9..name.len() - 1];
            let s = inner.trim_matches('"');
            Ok(PipeFunc::Rtrimstr(s.to_string()))
        }
        _ => Err(ExtractError::UnknownFunction(name.to_string())),
    }
}

/// Parse a default value for the alternative operator.
fn parse_default_value(s: &str) -> Result<Value, ExtractError> {
    // Try JSON parse first
    if let Ok(v) = serde_json::from_str::<Value>(s) {
        return Ok(v);
    }
    // Bare string
    Ok(Value::String(s.to_string()))
}

// ── Evaluation ──────────────────────────────────────────────────────────

/// Apply an extraction expression to a JSON value.
pub fn apply_extract(value: &Value, expr: &ExtractExpr) -> Result<Value, ExtractError> {
    match expr {
        ExtractExpr::Identity => Ok(value.clone()),

        ExtractExpr::Field(name) => get_field(value, name),

        ExtractExpr::Chain(segments) => apply_chain(value, segments),

        ExtractExpr::Iterate(inner) => {
            let base = apply_extract(value, inner)?;
            match &base {
                Value::Array(arr) => Ok(Value::Array(arr.clone())),
                Value::Null => Ok(Value::Array(vec![])),
                _ => Err(ExtractError::TypeError(format!(
                    "cannot iterate over {}",
                    value_type_name(&base)
                ))),
            }
        }

        ExtractExpr::Pipe(inner, func) => {
            let base = apply_extract(value, inner)?;
            apply_pipe_func(&base, func)
        }

        ExtractExpr::ObjectConstruct(fields) => {
            let mut map = serde_json::Map::new();
            for field in fields {
                let v = get_field(value, field).unwrap_or(Value::Null);
                map.insert(field.clone(), v);
            }
            Ok(Value::Object(map))
        }

        ExtractExpr::Alternative(inner, default) => {
            let result = apply_extract(value, inner)?;
            if result.is_null() {
                Ok(default.clone())
            } else {
                Ok(result)
            }
        }
    }
}

/// Access a field on a value.
fn get_field(value: &Value, name: &str) -> Result<Value, ExtractError> {
    match value {
        Value::Object(map) => Ok(map.get(name).cloned().unwrap_or(Value::Null)),
        Value::Null => Ok(Value::Null),
        _ => Err(ExtractError::TypeError(format!(
            "cannot index {} with field '{name}'",
            value_type_name(value)
        ))),
    }
}

/// Walk a chain of segments.
fn apply_chain(value: &Value, segments: &[ChainSegment]) -> Result<Value, ExtractError> {
    let mut current = value.clone();
    for seg in segments {
        match seg {
            ChainSegment::Field(name) => {
                current = get_field(&current, name)?;
            }
            ChainSegment::Index(idx) => {
                current = get_index(&current, *idx)?;
            }
            ChainSegment::IterArray => {
                // Should have been handled at parse time via Iterate
                match &current {
                    Value::Array(arr) => {
                        current = Value::Array(arr.clone());
                    }
                    Value::Null => {
                        current = Value::Array(vec![]);
                    }
                    _ => {
                        return Err(ExtractError::TypeError(format!(
                            "cannot iterate over {}",
                            value_type_name(&current)
                        )));
                    }
                }
            }
        }
    }
    Ok(current)
}

/// Access an array element by index.
fn get_index(value: &Value, idx: usize) -> Result<Value, ExtractError> {
    match value {
        Value::Array(arr) => {
            if idx < arr.len() {
                Ok(arr[idx].clone())
            } else {
                Err(ExtractError::IndexOutOfBounds {
                    index: idx,
                    len: arr.len(),
                })
            }
        }
        Value::Null => Ok(Value::Null),
        _ => Err(ExtractError::TypeError(format!(
            "cannot index {} with integer",
            value_type_name(value)
        ))),
    }
}

/// Apply a pipe function.
fn apply_pipe_func(value: &Value, func: &PipeFunc) -> Result<Value, ExtractError> {
    match func {
        PipeFunc::Length => match value {
            Value::Array(arr) => Ok(Value::Number(arr.len().into())),
            Value::Object(map) => Ok(Value::Number(map.len().into())),
            Value::String(s) => Ok(Value::Number(s.len().into())),
            Value::Null => Ok(Value::Number(0.into())),
            _ => Err(ExtractError::TypeError(format!(
                "{} has no length",
                value_type_name(value)
            ))),
        },
        PipeFunc::Keys => match value {
            Value::Object(map) => {
                let keys: Vec<Value> = map.keys().map(|k| Value::String(k.clone())).collect();
                Ok(Value::Array(keys))
            }
            Value::Array(arr) => {
                let keys: Vec<Value> = (0..arr.len()).map(|i| Value::Number(i.into())).collect();
                Ok(Value::Array(keys))
            }
            _ => Err(ExtractError::TypeError(format!(
                "{} has no keys",
                value_type_name(value)
            ))),
        },
        PipeFunc::Values => match value {
            Value::Object(map) => Ok(Value::Array(map.values().cloned().collect())),
            Value::Array(_) => Ok(value.clone()),
            _ => Err(ExtractError::TypeError(format!(
                "{} has no values",
                value_type_name(value)
            ))),
        },
        PipeFunc::Type => {
            let t = value_type_name(value);
            Ok(Value::String(t.to_string()))
        }
        PipeFunc::Not => {
            let truthy = is_truthy(value);
            Ok(Value::Bool(!truthy))
        }
        PipeFunc::Flatten => match value {
            Value::Array(arr) => {
                let mut out = Vec::new();
                for v in arr {
                    if let Value::Array(inner) = v {
                        out.extend(inner.iter().cloned());
                    } else {
                        out.push(v.clone());
                    }
                }
                Ok(Value::Array(out))
            }
            _ => Err(ExtractError::TypeError("flatten requires an array".into())),
        },
        PipeFunc::Reverse => match value {
            Value::Array(arr) => {
                let mut v = arr.clone();
                v.reverse();
                Ok(Value::Array(v))
            }
            Value::String(s) => Ok(Value::String(s.chars().rev().collect())),
            _ => Err(ExtractError::TypeError(
                "reverse requires array or string".into(),
            )),
        },
        PipeFunc::Min => match value {
            Value::Array(arr) if arr.is_empty() => Ok(Value::Null),
            Value::Array(arr) => {
                let min = arr
                    .iter()
                    .filter_map(|v| v.as_f64())
                    .reduce(f64::min)
                    .map_or(Value::Null, |n| {
                        serde_json::Number::from_f64(n).map_or(Value::Null, Value::Number)
                    });
                Ok(min)
            }
            _ => Err(ExtractError::TypeError("min requires an array".into())),
        },
        PipeFunc::Max => match value {
            Value::Array(arr) if arr.is_empty() => Ok(Value::Null),
            Value::Array(arr) => {
                let max = arr
                    .iter()
                    .filter_map(|v| v.as_f64())
                    .reduce(f64::max)
                    .map_or(Value::Null, |n| {
                        serde_json::Number::from_f64(n).map_or(Value::Null, Value::Number)
                    });
                Ok(max)
            }
            _ => Err(ExtractError::TypeError("max requires an array".into())),
        },
        PipeFunc::Unique => match value {
            Value::Array(arr) => {
                let mut seen = Vec::new();
                for v in arr {
                    if !seen.contains(v) {
                        seen.push(v.clone());
                    }
                }
                Ok(Value::Array(seen))
            }
            _ => Err(ExtractError::TypeError("unique requires an array".into())),
        },
        PipeFunc::Sort => match value {
            Value::Array(arr) => {
                let mut v = arr.clone();
                v.sort_by(|a, b| {
                    let fa = a.as_f64();
                    let fb = b.as_f64();
                    match (fa, fb) {
                        (Some(x), Some(y)) => {
                            x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal)
                        }
                        _ => {
                            let sa = format_extracted(a);
                            let sb = format_extracted(b);
                            sa.cmp(&sb)
                        }
                    }
                });
                Ok(Value::Array(v))
            }
            _ => Err(ExtractError::TypeError("sort requires an array".into())),
        },
        PipeFunc::First => match value {
            Value::Array(arr) if arr.is_empty() => Ok(Value::Null),
            Value::Array(arr) => Ok(arr[0].clone()),
            _ => Err(ExtractError::TypeError("first requires an array".into())),
        },
        PipeFunc::Last => match value {
            Value::Array(arr) if arr.is_empty() => Ok(Value::Null),
            Value::Array(arr) => Ok(arr[arr.len() - 1].clone()),
            _ => Err(ExtractError::TypeError("last requires an array".into())),
        },
        PipeFunc::Empty => Ok(Value::Null),
        PipeFunc::Ascii => match value {
            Value::Number(n) => {
                let code = n.as_u64().unwrap_or(0);
                if code <= 127 {
                    Ok(Value::String(
                        char::from_u32(code as u32).map_or(String::new(), |c| c.to_string()),
                    ))
                } else {
                    Ok(Value::Null)
                }
            }
            _ => Err(ExtractError::TypeError("ascii requires a number".into())),
        },
        PipeFunc::AsciiDowncase => match value {
            Value::String(s) => Ok(Value::String(s.to_lowercase())),
            _ => Err(ExtractError::TypeError(
                "ascii_downcase requires a string".into(),
            )),
        },
        PipeFunc::AsciiUpcase => match value {
            Value::String(s) => Ok(Value::String(s.to_uppercase())),
            _ => Err(ExtractError::TypeError(
                "ascii_upcase requires a string".into(),
            )),
        },
        PipeFunc::Tostring => match value {
            Value::String(_) => Ok(value.clone()),
            _ => Ok(Value::String(format_extracted(value))),
        },
        PipeFunc::Tonumber => match value {
            Value::Number(_) => Ok(value.clone()),
            Value::String(s) => {
                if let Ok(n) = s.parse::<i64>() {
                    Ok(Value::Number(n.into()))
                } else if let Ok(n) = s.parse::<f64>() {
                    Ok(serde_json::Number::from_f64(n).map_or(Value::Null, Value::Number))
                } else {
                    Err(ExtractError::TypeError(format!(
                        "cannot convert string '{s}' to number"
                    )))
                }
            }
            _ => Err(ExtractError::TypeError(format!(
                "cannot convert {} to number",
                value_type_name(value)
            ))),
        },
        PipeFunc::Ltrimstr(prefix) => match value {
            Value::String(s) => {
                let trimmed = s.strip_prefix(prefix.as_str()).unwrap_or(s);
                Ok(Value::String(trimmed.to_string()))
            }
            _ => Ok(value.clone()),
        },
        PipeFunc::Rtrimstr(suffix) => match value {
            Value::String(s) => {
                let trimmed = s.strip_suffix(suffix.as_str()).unwrap_or(s);
                Ok(Value::String(trimmed.to_string()))
            }
            _ => Ok(value.clone()),
        },
        PipeFunc::Add => match value {
            Value::Array(arr) => {
                if arr.is_empty() {
                    return Ok(Value::Null);
                }
                // If all numbers, sum them
                if arr.iter().all(|v| v.is_number()) {
                    let sum: f64 = arr.iter().filter_map(|v| v.as_f64()).sum();
                    Ok(serde_json::Number::from_f64(sum).map_or(Value::Null, Value::Number))
                } else if arr.iter().all(|v| v.is_string()) {
                    let concat: String = arr.iter().filter_map(|v| v.as_str()).collect();
                    Ok(Value::String(concat))
                } else if arr.iter().all(Value::is_array) {
                    let mut out = Vec::new();
                    for v in arr {
                        if let Value::Array(inner) = v {
                            out.extend(inner.iter().cloned());
                        }
                    }
                    Ok(Value::Array(out))
                } else {
                    Err(ExtractError::TypeError(
                        "add requires array of uniform types".into(),
                    ))
                }
            }
            _ => Err(ExtractError::TypeError("add requires an array".into())),
        },
        PipeFunc::Any => match value {
            Value::Array(arr) => Ok(Value::Bool(arr.iter().any(is_truthy))),
            _ => Err(ExtractError::TypeError("any requires an array".into())),
        },
        PipeFunc::All => match value {
            Value::Array(arr) => Ok(Value::Bool(arr.iter().all(is_truthy))),
            _ => Err(ExtractError::TypeError("all requires an array".into())),
        },
    }
}

/// Check if a value is truthy (jq semantics: false and null are falsy).
fn is_truthy(value: &Value) -> bool {
    !matches!(value, Value::Null | Value::Bool(false))
}

/// Return the jq type name for a value.
fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Format an extracted value as minimal JSON.
pub fn format_extracted(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("\"{s}\""),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "null".into()),
    }
}

/// Format an extracted value as raw string (without quotes for strings).
pub fn format_extracted_raw(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        _ => format_extracted(value),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Parse tests ──

    #[test]
    fn parse_identity() {
        let expr = parse_extract(".").unwrap();
        assert_eq!(expr, ExtractExpr::Identity);
    }

    #[test]
    fn parse_simple_field() {
        let expr = parse_extract(".name").unwrap();
        assert_eq!(expr, ExtractExpr::Field("name".into()));
    }

    #[test]
    fn parse_nested_fields() {
        let expr = parse_extract(".user.name").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Chain(vec![
                ChainSegment::Field("user".into()),
                ChainSegment::Field("name".into()),
            ])
        );
    }

    #[test]
    fn parse_array_index() {
        let expr = parse_extract(".[0]").unwrap();
        assert_eq!(expr, ExtractExpr::Chain(vec![ChainSegment::Index(0)]));
    }

    #[test]
    fn parse_array_iteration() {
        let expr = parse_extract(".[]").unwrap();
        assert_eq!(expr, ExtractExpr::Iterate(Box::new(ExtractExpr::Identity)));
    }

    #[test]
    fn parse_field_then_iterate() {
        let expr = parse_extract(".items[]").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Iterate(Box::new(ExtractExpr::Field("items".into())))
        );
    }

    #[test]
    fn parse_chained_field_index() {
        let expr = parse_extract(".data[0].name").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Chain(vec![
                ChainSegment::Field("data".into()),
                ChainSegment::Index(0),
                ChainSegment::Field("name".into()),
            ])
        );
    }

    #[test]
    fn parse_pipe_length() {
        let expr = parse_extract(".items | length").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Pipe(
                Box::new(ExtractExpr::Field("items".into())),
                PipeFunc::Length
            )
        );
    }

    #[test]
    fn parse_object_construct() {
        let expr = parse_extract("{name, age}").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::ObjectConstruct(vec!["name".into(), "age".into()])
        );
    }

    #[test]
    fn parse_alternative() {
        let expr = parse_extract(".name // \"unknown\"").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Alternative(
                Box::new(ExtractExpr::Field("name".into())),
                Value::String("unknown".into())
            )
        );
    }

    #[test]
    fn parse_error_empty() {
        let err = parse_extract("").unwrap_err();
        assert_eq!(err, ExtractError::ParseError("empty expression".into()));
    }

    #[test]
    fn parse_error_no_dot() {
        let err = parse_extract("name").unwrap_err();
        assert!(matches!(err, ExtractError::ParseError(_)));
    }

    #[test]
    fn parse_pipe_keys() {
        let expr = parse_extract(". | keys").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Pipe(Box::new(ExtractExpr::Identity), PipeFunc::Keys)
        );
    }

    #[test]
    fn parse_pipe_values() {
        let expr = parse_extract(". | values").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Pipe(Box::new(ExtractExpr::Identity), PipeFunc::Values)
        );
    }

    #[test]
    fn parse_pipe_type() {
        let expr = parse_extract(". | type").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Pipe(Box::new(ExtractExpr::Identity), PipeFunc::Type)
        );
    }

    #[test]
    fn parse_unknown_function() {
        let err = parse_extract(". | bogus").unwrap_err();
        assert_eq!(err, ExtractError::UnknownFunction("bogus".into()));
    }

    #[test]
    fn parse_deeply_nested() {
        let expr = parse_extract(".a.b.c.d.e").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Chain(vec![
                ChainSegment::Field("a".into()),
                ChainSegment::Field("b".into()),
                ChainSegment::Field("c".into()),
                ChainSegment::Field("d".into()),
                ChainSegment::Field("e".into()),
            ])
        );
    }

    #[test]
    fn parse_multiple_indices() {
        let expr = parse_extract(".[0][1]").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Chain(vec![ChainSegment::Index(0), ChainSegment::Index(1),])
        );
    }

    #[test]
    fn parse_field_with_index() {
        let expr = parse_extract(".items[2]").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Chain(vec![
                ChainSegment::Field("items".into()),
                ChainSegment::Index(2),
            ])
        );
    }

    #[test]
    fn parse_alternative_with_number() {
        let expr = parse_extract(".count // 0").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Alternative(
                Box::new(ExtractExpr::Field("count".into())),
                Value::Number(0.into())
            )
        );
    }

    #[test]
    fn parse_object_construct_single() {
        let expr = parse_extract("{id}").unwrap();
        assert_eq!(expr, ExtractExpr::ObjectConstruct(vec!["id".into()]));
    }

    #[test]
    fn parse_object_construct_many() {
        let expr = parse_extract("{a, b, c, d}").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::ObjectConstruct(vec!["a".into(), "b".into(), "c".into(), "d".into(),])
        );
    }

    #[test]
    fn parse_pipe_not() {
        let expr = parse_extract(". | not").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Pipe(Box::new(ExtractExpr::Identity), PipeFunc::Not)
        );
    }

    // ── Apply tests ──

    #[test]
    fn apply_identity() {
        let v = json!({"x": 1});
        let expr = parse_extract(".").unwrap();
        let result = apply_extract(&v, &expr).unwrap();
        assert_eq!(result, v);
    }

    #[test]
    fn apply_simple_field() {
        let v = json!({"name": "alice"});
        let expr = parse_extract(".name").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("alice"));
    }

    #[test]
    fn apply_nested_field() {
        let v = json!({"user": {"name": "bob"}});
        let expr = parse_extract(".user.name").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("bob"));
    }

    #[test]
    fn apply_array_index() {
        let v = json!([10, 20, 30]);
        let expr = parse_extract(".[1]").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(20));
    }

    #[test]
    fn apply_array_iteration() {
        let v = json!([1, 2, 3]);
        let expr = parse_extract(".[]").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([1, 2, 3]));
    }

    #[test]
    fn apply_field_array_iteration() {
        let v = json!({"items": [1, 2]});
        let expr = parse_extract(".items[]").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([1, 2]));
    }

    #[test]
    fn apply_chained_field_index() {
        let v = json!({"data": [{"name": "a"}, {"name": "b"}]});
        let expr = parse_extract(".data[0].name").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("a"));
    }

    #[test]
    fn apply_pipe_length_array() {
        let v = json!({"items": [1, 2, 3]});
        let expr = parse_extract(".items | length").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(3));
    }

    #[test]
    fn apply_pipe_length_object() {
        let v = json!({"a": 1, "b": 2});
        let expr = parse_extract(". | length").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(2));
    }

    #[test]
    fn apply_pipe_length_string() {
        let v = json!("hello");
        let expr = parse_extract(". | length").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(5));
    }

    #[test]
    fn apply_pipe_length_null() {
        let v = json!(null);
        let expr = parse_extract(". | length").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(0));
    }

    #[test]
    fn apply_object_construct() {
        let v = json!({"name": "alice", "age": 30, "city": "NYC"});
        let expr = parse_extract("{name, age}").unwrap();
        let result = apply_extract(&v, &expr).unwrap();
        assert_eq!(result, json!({"name": "alice", "age": 30}));
    }

    #[test]
    fn apply_alternative_present() {
        let v = json!({"name": "alice"});
        let expr = parse_extract(".name // \"unknown\"").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("alice"));
    }

    #[test]
    fn apply_alternative_missing() {
        let v = json!({"age": 30});
        let expr = parse_extract(".name // \"unknown\"").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("unknown"));
    }

    #[test]
    fn apply_alternative_null_value() {
        let v = json!({"name": null});
        let expr = parse_extract(".name // \"default\"").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("default"));
    }

    #[test]
    fn apply_missing_field_returns_null() {
        let v = json!({"a": 1});
        let expr = parse_extract(".b").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), Value::Null);
    }

    #[test]
    fn apply_deeply_nested() {
        let v = json!({"a": {"b": {"c": {"d": 42}}}});
        let expr = parse_extract(".a.b.c.d").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(42));
    }

    #[test]
    fn apply_nested_missing_intermediate() {
        let v = json!({"a": {"x": 1}});
        let expr = parse_extract(".a.b.c").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), Value::Null);
    }

    #[test]
    fn apply_index_out_of_bounds() {
        let v = json!([1, 2]);
        let expr = parse_extract(".[5]").unwrap();
        let err = apply_extract(&v, &expr).unwrap_err();
        assert_eq!(err, ExtractError::IndexOutOfBounds { index: 5, len: 2 });
    }

    #[test]
    fn apply_field_on_number() {
        let v = json!(42);
        let expr = parse_extract(".name").unwrap();
        let err = apply_extract(&v, &expr).unwrap_err();
        assert!(matches!(err, ExtractError::TypeError(_)));
    }

    #[test]
    fn apply_index_on_string() {
        let v = json!("hello");
        let expr = parse_extract(".[0]").unwrap();
        let err = apply_extract(&v, &expr).unwrap_err();
        assert!(matches!(err, ExtractError::TypeError(_)));
    }

    #[test]
    fn apply_iterate_on_non_array() {
        let v = json!("hello");
        let expr = parse_extract(".[]").unwrap();
        let err = apply_extract(&v, &expr).unwrap_err();
        assert!(matches!(err, ExtractError::TypeError(_)));
    }

    #[test]
    fn apply_pipe_keys_object() {
        let v = json!({"b": 1, "a": 2});
        let expr = parse_extract(". | keys").unwrap();
        let result = apply_extract(&v, &expr).unwrap();
        let mut keys: Vec<String> = result
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[test]
    fn apply_pipe_keys_array() {
        let v = json!([10, 20, 30]);
        let expr = parse_extract(". | keys").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([0, 1, 2]));
    }

    #[test]
    fn apply_pipe_values_object() {
        let v = json!({"a": 1, "b": 2});
        let expr = parse_extract(". | values").unwrap();
        let result = apply_extract(&v, &expr).unwrap();
        // Values from a BTreeMap are sorted by key
        assert_eq!(result, json!([1, 2]));
    }

    #[test]
    fn apply_pipe_type_string() {
        let v = json!("hello");
        let expr = parse_extract(". | type").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("string"));
    }

    #[test]
    fn apply_pipe_type_number() {
        let v = json!(42);
        let expr = parse_extract(". | type").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("number"));
    }

    #[test]
    fn apply_pipe_type_array() {
        let v = json!([1]);
        let expr = parse_extract(". | type").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("array"));
    }

    #[test]
    fn apply_pipe_type_object() {
        let v = json!({"a": 1});
        let expr = parse_extract(". | type").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("object"));
    }

    #[test]
    fn apply_pipe_type_bool() {
        let v = json!(true);
        let expr = parse_extract(". | type").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("boolean"));
    }

    #[test]
    fn apply_pipe_type_null() {
        let v = json!(null);
        let expr = parse_extract(". | type").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("null"));
    }

    #[test]
    fn apply_pipe_not_true() {
        let v = json!(true);
        let expr = parse_extract(". | not").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(false));
    }

    #[test]
    fn apply_pipe_not_false() {
        let v = json!(false);
        let expr = parse_extract(". | not").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(true));
    }

    #[test]
    fn apply_pipe_not_null() {
        let v = json!(null);
        let expr = parse_extract(". | not").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(true));
    }

    #[test]
    fn apply_pipe_not_number() {
        let v = json!(0);
        let expr = parse_extract(". | not").unwrap();
        // In jq, 0 is truthy
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(false));
    }

    #[test]
    fn apply_pipe_flatten() {
        let v = json!([[1, 2], [3], [4, 5]]);
        let expr = parse_extract(". | flatten").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([1, 2, 3, 4, 5]));
    }

    #[test]
    fn apply_pipe_flatten_mixed() {
        let v = json!([[1], 2, [3]]);
        let expr = parse_extract(". | flatten").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([1, 2, 3]));
    }

    #[test]
    fn apply_pipe_reverse_array() {
        let v = json!([1, 2, 3]);
        let expr = parse_extract(". | reverse").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([3, 2, 1]));
    }

    #[test]
    fn apply_pipe_reverse_string() {
        let v = json!("abc");
        let expr = parse_extract(". | reverse").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("cba"));
    }

    #[test]
    fn apply_pipe_min() {
        let v = json!([3, 1, 2]);
        let expr = parse_extract(". | min").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(1.0));
    }

    #[test]
    fn apply_pipe_max() {
        let v = json!([3, 1, 2]);
        let expr = parse_extract(". | max").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(3.0));
    }

    #[test]
    fn apply_pipe_min_empty() {
        let v = json!([]);
        let expr = parse_extract(". | min").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), Value::Null);
    }

    #[test]
    fn apply_pipe_unique() {
        let v = json!([1, 2, 1, 3, 2]);
        let expr = parse_extract(". | unique").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([1, 2, 3]));
    }

    #[test]
    fn apply_pipe_sort() {
        let v = json!([3, 1, 2]);
        let expr = parse_extract(". | sort").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([1, 2, 3]));
    }

    #[test]
    fn apply_pipe_first() {
        let v = json!([10, 20, 30]);
        let expr = parse_extract(". | first").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(10));
    }

    #[test]
    fn apply_pipe_last() {
        let v = json!([10, 20, 30]);
        let expr = parse_extract(". | last").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(30));
    }

    #[test]
    fn apply_pipe_first_empty() {
        let v = json!([]);
        let expr = parse_extract(". | first").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), Value::Null);
    }

    #[test]
    fn apply_pipe_tostring_number() {
        let v = json!(42);
        let expr = parse_extract(". | tostring").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("42"));
    }

    #[test]
    fn apply_pipe_tostring_string() {
        let v = json!("hello");
        let expr = parse_extract(". | tostring").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("hello"));
    }

    #[test]
    fn apply_pipe_tonumber_string() {
        let v = json!("42");
        let expr = parse_extract(". | tonumber").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(42));
    }

    #[test]
    fn apply_pipe_tonumber_float() {
        let v = json!("2.5");
        let expr = parse_extract(". | tonumber").unwrap();
        let result = apply_extract(&v, &expr).unwrap();
        assert!((result.as_f64().unwrap() - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn apply_pipe_tonumber_invalid() {
        let v = json!("abc");
        let expr = parse_extract(". | tonumber").unwrap();
        assert!(apply_extract(&v, &expr).is_err());
    }

    #[test]
    fn apply_pipe_add_numbers() {
        let v = json!([1, 2, 3]);
        let expr = parse_extract(". | add").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(6.0));
    }

    #[test]
    fn apply_pipe_add_strings() {
        let v = json!(["a", "b", "c"]);
        let expr = parse_extract(". | add").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("abc"));
    }

    #[test]
    fn apply_pipe_add_arrays() {
        let v = json!([[1, 2], [3], [4, 5]]);
        let expr = parse_extract(". | add").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([1, 2, 3, 4, 5]));
    }

    #[test]
    fn apply_pipe_add_empty() {
        let v = json!([]);
        let expr = parse_extract(". | add").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), Value::Null);
    }

    #[test]
    fn apply_pipe_any_true() {
        let v = json!([false, true, false]);
        let expr = parse_extract(". | any").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(true));
    }

    #[test]
    fn apply_pipe_any_false() {
        let v = json!([false, null, false]);
        let expr = parse_extract(". | any").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(false));
    }

    #[test]
    fn apply_pipe_all_true() {
        let v = json!([true, 1, "x"]);
        let expr = parse_extract(". | all").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(true));
    }

    #[test]
    fn apply_pipe_all_false() {
        let v = json!([true, null, 1]);
        let expr = parse_extract(". | all").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(false));
    }

    #[test]
    fn apply_pipe_ascii_downcase() {
        let v = json!("HELLO");
        let expr = parse_extract(". | ascii_downcase").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("hello"));
    }

    #[test]
    fn apply_pipe_ascii_upcase() {
        let v = json!("hello");
        let expr = parse_extract(". | ascii_upcase").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("HELLO"));
    }

    // ── Format tests ──

    #[test]
    fn format_null() {
        assert_eq!(format_extracted(&Value::Null), "null");
    }

    #[test]
    fn format_bool() {
        assert_eq!(format_extracted(&json!(true)), "true");
        assert_eq!(format_extracted(&json!(false)), "false");
    }

    #[test]
    fn format_number() {
        assert_eq!(format_extracted(&json!(42)), "42");
    }

    #[test]
    fn format_string() {
        assert_eq!(format_extracted(&json!("hello")), "\"hello\"");
    }

    #[test]
    fn format_array() {
        let v = json!([1, 2, 3]);
        let s = format_extracted(&v);
        assert_eq!(s, "[1,2,3]");
    }

    #[test]
    fn format_object() {
        let v = json!({"a": 1});
        let s = format_extracted(&v);
        assert_eq!(s, "{\"a\":1}");
    }

    #[test]
    fn format_raw_string() {
        assert_eq!(format_extracted_raw(&json!("hello")), "hello");
    }

    #[test]
    fn format_raw_number() {
        assert_eq!(format_extracted_raw(&json!(42)), "42");
    }

    // ── Edge case tests ──

    #[test]
    fn edge_empty_object() {
        let v = json!({});
        let expr = parse_extract(".name").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), Value::Null);
    }

    #[test]
    fn edge_empty_array() {
        let v = json!([]);
        let expr = parse_extract(".[]").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([]));
    }

    #[test]
    fn edge_null_input() {
        let v = Value::Null;
        let expr = parse_extract(".name").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), Value::Null);
    }

    #[test]
    fn edge_null_chain() {
        let v = Value::Null;
        let expr = parse_extract(".a.b.c").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), Value::Null);
    }

    #[test]
    fn edge_nested_array_index() {
        let v = json!({"matrix": [[1, 2], [3, 4]]});
        let expr = parse_extract(".matrix[1][0]").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(3));
    }

    #[test]
    fn edge_object_construct_missing_field() {
        let v = json!({"name": "alice"});
        let expr = parse_extract("{name, age}").unwrap();
        let result = apply_extract(&v, &expr).unwrap();
        assert_eq!(result, json!({"name": "alice", "age": null}));
    }

    #[test]
    fn edge_alternative_with_false() {
        // `false` is not null, so should NOT use default
        let v = json!({"flag": false});
        let expr = parse_extract(".flag // true").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(false));
    }

    #[test]
    fn edge_alternative_with_zero() {
        // `0` is not null, so should NOT use default
        let v = json!({"count": 0});
        let expr = parse_extract(".count // 99").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(0));
    }

    #[test]
    fn edge_length_on_number_error() {
        let v = json!(42);
        let expr = parse_extract(". | length").unwrap();
        assert!(apply_extract(&v, &expr).is_err());
    }

    #[test]
    fn edge_empty_string_length() {
        let v = json!("");
        let expr = parse_extract(". | length").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(0));
    }

    #[test]
    fn edge_large_array_index() {
        let v = json!([1]);
        let expr = parse_extract(".[999]").unwrap();
        let err = apply_extract(&v, &expr).unwrap_err();
        assert_eq!(err, ExtractError::IndexOutOfBounds { index: 999, len: 1 });
    }

    #[test]
    fn edge_iterate_null() {
        let v = json!({"items": null});
        let expr = parse_extract(".items[]").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([]));
    }

    #[test]
    fn edge_sort_strings() {
        let v = json!(["banana", "apple", "cherry"]);
        let expr = parse_extract(". | sort").unwrap();
        assert_eq!(
            apply_extract(&v, &expr).unwrap(),
            json!(["apple", "banana", "cherry"])
        );
    }

    #[test]
    fn edge_unique_empty() {
        let v = json!([]);
        let expr = parse_extract(". | unique").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([]));
    }

    #[test]
    fn edge_flatten_empty() {
        let v = json!([]);
        let expr = parse_extract(". | flatten").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([]));
    }

    #[test]
    fn edge_reverse_empty() {
        let v = json!([]);
        let expr = parse_extract(". | reverse").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([]));
    }

    #[test]
    fn edge_index_on_null() {
        let v = Value::Null;
        let expr = parse_extract(".[0]").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), Value::Null);
    }

    #[test]
    fn extract_result_single_to_value() {
        let r = ExtractResult::Single(json!(42));
        assert_eq!(r.into_value(), json!(42));
    }

    #[test]
    fn extract_result_multiple_to_value() {
        let r = ExtractResult::Multiple(vec![json!(1), json!(2)]);
        assert_eq!(r.into_value(), json!([1, 2]));
    }

    #[test]
    fn extract_result_null_to_value() {
        let r = ExtractResult::Null;
        assert_eq!(r.into_value(), Value::Null);
    }

    #[test]
    fn error_display_parse() {
        let e = ExtractError::ParseError("bad".into());
        assert_eq!(format!("{e}"), "parse error: bad");
    }

    #[test]
    fn error_display_type() {
        let e = ExtractError::TypeError("oops".into());
        assert_eq!(format!("{e}"), "type error: oops");
    }

    #[test]
    fn error_display_index() {
        let e = ExtractError::IndexOutOfBounds { index: 5, len: 3 };
        assert_eq!(format!("{e}"), "index 5 out of bounds (length 3)");
    }

    #[test]
    fn error_display_unknown_func() {
        let e = ExtractError::UnknownFunction("foo".into());
        assert_eq!(format!("{e}"), "unknown function: foo");
    }

    #[test]
    fn parse_pipe_sort_func() {
        let expr = parse_extract(". | sort").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Pipe(Box::new(ExtractExpr::Identity), PipeFunc::Sort)
        );
    }

    #[test]
    fn parse_pipe_unique_func() {
        let expr = parse_extract(". | unique").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Pipe(Box::new(ExtractExpr::Identity), PipeFunc::Unique)
        );
    }

    #[test]
    fn parse_pipe_flatten_func() {
        let expr = parse_extract(". | flatten").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Pipe(Box::new(ExtractExpr::Identity), PipeFunc::Flatten)
        );
    }

    #[test]
    fn parse_pipe_reverse_func() {
        let expr = parse_extract(". | reverse").unwrap();
        assert_eq!(
            expr,
            ExtractExpr::Pipe(Box::new(ExtractExpr::Identity), PipeFunc::Reverse)
        );
    }

    #[test]
    fn complex_chained_extract() {
        let v = json!({
            "users": [
                {"name": "alice", "scores": [90, 85]},
                {"name": "bob", "scores": [70, 95]}
            ]
        });
        let expr = parse_extract(".users[1].scores[0]").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(70));
    }

    #[test]
    fn complex_field_with_length() {
        let v = json!({"tags": ["a", "b", "c", "d"]});
        let expr = parse_extract(".tags | length").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(4));
    }

    #[test]
    fn complex_keys_on_nested() {
        let v = json!({"config": {"host": "x", "port": 80}});
        let expr = parse_extract(".config | keys").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(["host", "port"]));
    }

    #[test]
    fn complex_alternative_chain() {
        let v = json!({"outer": {}});
        let expr = parse_extract(".outer.inner // \"fallback\"").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("fallback"));
    }

    #[test]
    fn apply_pipe_empty() {
        let v = json!(42);
        let expr = parse_extract(". | empty").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), Value::Null);
    }

    #[test]
    fn apply_pipe_ascii_char() {
        let v = json!(65);
        let expr = parse_extract(". | ascii").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("A"));
    }

    #[test]
    fn edge_object_construct_on_null() {
        let v = Value::Null;
        let expr = parse_extract("{x}").unwrap();
        let result = apply_extract(&v, &expr).unwrap();
        assert_eq!(result, json!({"x": null}));
    }

    #[test]
    fn edge_max_on_empty() {
        let v = json!([]);
        let expr = parse_extract(". | max").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), Value::Null);
    }

    #[test]
    fn edge_last_on_empty() {
        let v = json!([]);
        let expr = parse_extract(". | last").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), Value::Null);
    }

    #[test]
    fn edge_reverse_string_empty() {
        let v = json!("");
        let expr = parse_extract(". | reverse").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(""));
    }

    #[test]
    fn edge_unique_all_same() {
        let v = json!([1, 1, 1]);
        let expr = parse_extract(". | unique").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!([1]));
    }

    #[test]
    fn apply_pipe_ltrimstr() {
        let expr = parse_extract(". | ltrimstr(\"hello \")").unwrap();
        let v = json!("hello world");
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("world"));
    }

    #[test]
    fn apply_pipe_ltrimstr_no_match() {
        let expr = parse_extract(". | ltrimstr(\"xyz\")").unwrap();
        let v = json!("hello");
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("hello"));
    }

    #[test]
    fn apply_pipe_rtrimstr() {
        let expr = parse_extract(". | rtrimstr(\".txt\")").unwrap();
        let v = json!("file.txt");
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("file"));
    }

    #[test]
    fn apply_pipe_rtrimstr_no_match() {
        let expr = parse_extract(". | rtrimstr(\".rs\")").unwrap();
        let v = json!("file.txt");
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!("file.txt"));
    }

    #[test]
    fn edge_alternative_with_empty_string() {
        // Empty string is not null, should NOT use default
        let v = json!({"name": ""});
        let expr = parse_extract(".name // \"default\"").unwrap();
        assert_eq!(apply_extract(&v, &expr).unwrap(), json!(""));
    }

    #[test]
    fn edge_sort_mixed_types() {
        let v = json!([3, "a", 1, "b"]);
        let expr = parse_extract(". | sort").unwrap();
        // Should not panic — sorts by string representation for non-uniform types
        let result = apply_extract(&v, &expr).unwrap();
        assert!(result.is_array());
    }

    #[test]
    fn edge_add_mixed_types_error() {
        let v = json!([1, "a"]);
        let expr = parse_extract(". | add").unwrap();
        assert!(apply_extract(&v, &expr).is_err());
    }
}
