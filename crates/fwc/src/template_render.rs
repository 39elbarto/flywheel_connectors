//! Lightweight Handlebars-style template rendering engine.
//!
//! Implements a subset of Handlebars syntax without external dependencies:
//! - `{{field}}` — simple interpolation
//! - `{{field.nested}}` — dot-path access
//! - `{{#if field}}...{{/if}}` — conditional
//! - `{{#each items}}...{{/each}}` — iteration with `{{this}}` and `{{@index}}`
//! - `{{#unless field}}...{{/unless}}` — negated conditional
//! - `{{field | upper}}` — pipe to builtin filters

use serde_json::Value;
use std::fmt;

// ── Types ───────────────────────────────────────────────────────────────

/// A parsed template, ready for rendering.
#[derive(Clone, Debug, PartialEq)]
pub struct Template {
    nodes: Vec<TemplateNode>,
}

/// A single node in the parsed template AST.
#[derive(Clone, Debug, PartialEq)]
enum TemplateNode {
    /// Raw literal text.
    Literal(String),
    /// Variable interpolation: `{{path}}` or `{{path | filter}}`.
    Interpolation {
        path: TemplatePath,
        filters: Vec<TemplateFilter>,
    },
    /// Conditional block: `{{#if path}}...{{/if}}`.
    If {
        path: TemplatePath,
        body: Vec<TemplateNode>,
        else_body: Vec<TemplateNode>,
    },
    /// Negated conditional: `{{#unless path}}...{{/unless}}`.
    Unless {
        path: TemplatePath,
        body: Vec<TemplateNode>,
    },
    /// Iteration: `{{#each path}}...{{/each}}`.
    Each {
        path: TemplatePath,
        body: Vec<TemplateNode>,
    },
}

/// A dot-separated path for value lookup.
#[derive(Clone, Debug, PartialEq)]
struct TemplatePath {
    segments: Vec<String>,
}

impl TemplatePath {
    fn new(s: &str) -> Self {
        Self {
            segments: s.split('.').map(|p| p.to_string()).collect(),
        }
    }

    fn is_this(&self) -> bool {
        self.segments.len() == 1 && self.segments[0] == "this"
    }

    fn is_index(&self) -> bool {
        self.segments.len() == 1 && self.segments[0] == "@index"
    }
}

/// Built-in template filters.
#[derive(Clone, Debug, PartialEq)]
enum TemplateFilter {
    Upper,
    Lower,
    Trim,
    Length,
    Default(String),
    Json,
    UrlEncode,
    HtmlEscape,
    Capitalize,
    Truncate(usize),
    Replace(String, String),
    PadLeft(usize),
    PadRight(usize),
    Repeat(usize),
    Reverse,
    Split(String),
    Join(String),
    Base64,
    Base64Decode,
    StripTags,
    Pluralize(String, String),
    Indent(usize),
}

/// Template parse/render errors.
#[derive(Clone, Debug, PartialEq)]
pub enum TemplateError {
    /// Parse error at a character offset.
    ParseError { message: String, offset: usize },
    /// A block was not properly closed.
    UnclosedBlock(String),
    /// A close tag didn't match the open tag.
    MismatchedBlock { expected: String, found: String },
    /// Render-time error.
    RenderError(String),
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseError { message, offset } => {
                write!(f, "parse error at offset {offset}: {message}")
            }
            Self::UnclosedBlock(name) => write!(f, "unclosed block: {{{{#{name}}}}}"),
            Self::MismatchedBlock { expected, found } => {
                write!(
                    f,
                    "mismatched block: expected {{{{/{expected}}}}} but found {{{{/{found}}}}}"
                )
            }
            Self::RenderError(msg) => write!(f, "render error: {msg}"),
        }
    }
}

impl std::error::Error for TemplateError {}

/// Data available during rendering.
#[derive(Clone, Debug)]
pub struct RenderContext {
    /// The root data object.
    pub data: Value,
    /// Current iteration index (set inside `{{#each}}`).
    pub index: Option<usize>,
    /// Current iteration value (set inside `{{#each}}`).
    pub current: Option<Value>,
}

impl RenderContext {
    /// Create a new context from root data.
    pub fn new(data: Value) -> Self {
        Self {
            data,
            index: None,
            current: None,
        }
    }

    /// Create a child context for an each-loop iteration.
    fn child_for_each(&self, index: usize, value: Value) -> Self {
        Self {
            data: self.data.clone(),
            index: Some(index),
            current: Some(value),
        }
    }
}

// ── Parsing ─────────────────────────────────────────────────────────────

/// Parse a template string into a `Template`.
pub fn parse_template(s: &str) -> Result<Template, TemplateError> {
    let nodes = parse_nodes(s, None)?;
    Ok(Template { nodes })
}

/// Parse template nodes, optionally stopping at a closing block tag.
fn parse_nodes(s: &str, end_block: Option<&str>) -> Result<Vec<TemplateNode>, TemplateError> {
    let mut nodes = Vec::new();
    let mut remaining = s;

    while !remaining.is_empty() {
        // Check for escaped braces: `\{{` → literal `{{`
        if remaining.starts_with("\\{{") {
            nodes.push(TemplateNode::Literal("{{".to_string()));
            remaining = &remaining[3..];
            continue;
        }

        if let Some(idx) = remaining.find("{{") {
            // Push literal before the tag
            if idx > 0 {
                nodes.push(TemplateNode::Literal(remaining[..idx].to_string()));
            }
            remaining = &remaining[idx..];

            // Find the closing `}}`
            let close = remaining
                .find("}}")
                .ok_or_else(|| TemplateError::ParseError {
                    message: "unclosed {{ tag".into(),
                    offset: s.len() - remaining.len(),
                })?;
            let tag_content = remaining[2..close].trim();
            remaining = &remaining[close + 2..];

            // Block open: `{{#if ...}}`, `{{#each ...}}`, `{{#unless ...}}`
            if let Some(rest) = tag_content.strip_prefix('#') {
                let (block_type, arg) = split_block_tag(rest);
                match block_type {
                    "if" => {
                        let path = TemplatePath::new(arg);
                        let (body, else_body, after) = parse_block_with_else(remaining, "if")?;
                        remaining = after;
                        nodes.push(TemplateNode::If {
                            path,
                            body,
                            else_body,
                        });
                    }
                    "unless" => {
                        let path = TemplatePath::new(arg);
                        let (body, after) = parse_block_body(remaining, "unless")?;
                        remaining = after;
                        nodes.push(TemplateNode::Unless { path, body });
                    }
                    "each" => {
                        let path = TemplatePath::new(arg);
                        let (body, after) = parse_block_body(remaining, "each")?;
                        remaining = after;
                        nodes.push(TemplateNode::Each { path, body });
                    }
                    _ => {
                        return Err(TemplateError::ParseError {
                            message: format!("unknown block type: {block_type}"),
                            offset: s.len() - remaining.len(),
                        });
                    }
                }
            } else if let Some(rest) = tag_content.strip_prefix('/') {
                // Block close tag
                let block_name = rest.trim();
                if let Some(expected) = end_block {
                    if block_name == expected {
                        // Return remaining text after closing tag for the caller
                        // But we can't easily return remaining here due to our
                        // architecture. Instead, we handle this in parse_block_body.
                        // If we're here, it means we found the close in the
                        // top-level parser, which is an error.
                        return Err(TemplateError::MismatchedBlock {
                            expected: expected.into(),
                            found: block_name.into(),
                        });
                    }
                }
                return Err(TemplateError::ParseError {
                    message: format!("unexpected closing tag: {{{{/{block_name}}}}}"),
                    offset: s.len() - remaining.len(),
                });
            } else if tag_content == "else" {
                // `{{else}}` — only valid inside a block, which is handled
                // by parse_block_with_else. If we see it here, it's an error.
                if end_block.is_some() {
                    // We'll handle this in the block parser
                    return Err(TemplateError::ParseError {
                        message: "unexpected {{else}} outside of if block".into(),
                        offset: s.len() - remaining.len(),
                    });
                }
                return Err(TemplateError::ParseError {
                    message: "{{else}} outside of block".into(),
                    offset: s.len() - remaining.len(),
                });
            } else {
                // Interpolation: `{{path}}` or `{{path | filter}}`
                let (path, filters) = parse_interpolation(tag_content)?;
                nodes.push(TemplateNode::Interpolation { path, filters });
            }
        } else {
            // No more tags — rest is literal
            nodes.push(TemplateNode::Literal(remaining.to_string()));
            remaining = "";
        }
    }

    if let Some(expected) = end_block {
        return Err(TemplateError::UnclosedBlock(expected.into()));
    }
    Ok(nodes)
}

/// Parse a block body until the matching close tag.
/// Returns the body nodes and the remaining text after the close tag.
fn parse_block_body<'a>(
    s: &'a str,
    block_type: &str,
) -> Result<(Vec<TemplateNode>, &'a str), TemplateError> {
    let close_tag = ["{{/", block_type, "}}"].concat();
    // Find the close tag, accounting for nesting
    let end_pos = find_close_tag(s, block_type)?;
    let body_text = &s[..end_pos];
    let after = &s[end_pos + close_tag.len()..];
    let body = parse_nodes_inner(body_text)?;
    Ok((body, after))
}

/// Parse a block body with optional `{{else}}` clause.
fn parse_block_with_else<'a>(
    s: &'a str,
    block_type: &str,
) -> Result<(Vec<TemplateNode>, Vec<TemplateNode>, &'a str), TemplateError> {
    let close_tag = ["{{/", block_type, "}}"].concat();
    let end_pos = find_close_tag(s, block_type)?;
    let body_text = &s[..end_pos];
    let after = &s[end_pos + close_tag.len()..];

    // Check for {{else}} in the body (at the same nesting level)
    if let Some(else_pos) = find_else_tag(body_text)? {
        let if_body_text = &body_text[..else_pos];
        let else_body_text = &body_text[else_pos + "{{else}}".len()..];
        let if_body = parse_nodes_inner(if_body_text)?;
        let else_body = parse_nodes_inner(else_body_text)?;
        Ok((if_body, else_body, after))
    } else {
        let body = parse_nodes_inner(body_text)?;
        Ok((body, vec![], after))
    }
}

/// Find the position of `{{else}}` at the top level (not nested).
fn find_else_tag(s: &str) -> Result<Option<usize>, TemplateError> {
    let mut depth = 0i32;
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            // Check for block open
            let rest = &s[i + 2..];
            if let Some(close) = rest.find("}}") {
                let tag = rest[..close].trim();
                if tag.starts_with('#') {
                    depth += 1;
                } else if tag.starts_with('/') {
                    depth -= 1;
                } else if tag == "else" && depth == 0 {
                    return Ok(Some(i));
                }
                i += 2 + close + 2;
                continue;
            }
        }
        i += 1;
    }
    Ok(None)
}

/// Find the matching close tag for a block type, handling nesting.
fn find_close_tag(s: &str, block_type: &str) -> Result<usize, TemplateError> {
    let open_prefix = ["{{#", block_type].concat();
    let close_tag = ["{{/", block_type, "}}"].concat();
    let mut depth = 1i32;
    let mut i = 0;
    let bytes = s.as_bytes();

    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            let rest = &s[i..];
            if rest.starts_with(&close_tag) {
                depth -= 1;
                if depth == 0 {
                    return Ok(i);
                }
                i += close_tag.len();
                continue;
            }
            if rest.starts_with(&open_prefix) {
                // Check it's actually an opening tag (followed by space or }})
                let after_prefix = &rest[open_prefix.len()..];
                if after_prefix.starts_with("}}") || after_prefix.starts_with(' ') {
                    depth += 1;
                }
            }
        }
        i += 1;
    }

    Err(TemplateError::UnclosedBlock(block_type.into()))
}

/// Parse nodes without block-end checking (for body text extraction).
fn parse_nodes_inner(s: &str) -> Result<Vec<TemplateNode>, TemplateError> {
    let mut nodes = Vec::new();
    let mut remaining = s;

    while !remaining.is_empty() {
        if remaining.starts_with("\\{{") {
            nodes.push(TemplateNode::Literal("{{".to_string()));
            remaining = &remaining[3..];
            continue;
        }

        if let Some(idx) = remaining.find("{{") {
            if idx > 0 {
                nodes.push(TemplateNode::Literal(remaining[..idx].to_string()));
            }
            remaining = &remaining[idx..];

            let close = remaining
                .find("}}")
                .ok_or_else(|| TemplateError::ParseError {
                    message: "unclosed {{ tag".into(),
                    offset: 0,
                })?;
            let tag_content = remaining[2..close].trim();
            remaining = &remaining[close + 2..];

            if let Some(rest) = tag_content.strip_prefix('#') {
                let (block_type, arg) = split_block_tag(rest);
                match block_type {
                    "if" => {
                        let path = TemplatePath::new(arg);
                        let (body, else_body, after) = parse_block_with_else(remaining, "if")?;
                        remaining = after;
                        nodes.push(TemplateNode::If {
                            path,
                            body,
                            else_body,
                        });
                    }
                    "unless" => {
                        let path = TemplatePath::new(arg);
                        let (body, after) = parse_block_body(remaining, "unless")?;
                        remaining = after;
                        nodes.push(TemplateNode::Unless { path, body });
                    }
                    "each" => {
                        let path = TemplatePath::new(arg);
                        let (body, after) = parse_block_body(remaining, "each")?;
                        remaining = after;
                        nodes.push(TemplateNode::Each { path, body });
                    }
                    _ => {
                        return Err(TemplateError::ParseError {
                            message: format!("unknown block type: {block_type}"),
                            offset: 0,
                        });
                    }
                }
            } else if tag_content.starts_with('/') {
                // This should not happen inside parse_nodes_inner if blocks
                // are properly extracted. Treat as error.
                return Err(TemplateError::ParseError {
                    message: format!("unexpected close tag: {tag_content}"),
                    offset: 0,
                });
            } else if tag_content == "else" {
                // Should be handled by the block parser
                return Err(TemplateError::ParseError {
                    message: "unexpected {{else}}".into(),
                    offset: 0,
                });
            } else {
                let (path, filters) = parse_interpolation(tag_content)?;
                nodes.push(TemplateNode::Interpolation { path, filters });
            }
        } else {
            nodes.push(TemplateNode::Literal(remaining.to_string()));
            remaining = "";
        }
    }

    Ok(nodes)
}

/// Split a block tag into (type, argument).
fn split_block_tag(s: &str) -> (&str, &str) {
    if let Some(idx) = s.find(' ') {
        (&s[..idx], s[idx + 1..].trim())
    } else {
        (s, "")
    }
}

/// Parse an interpolation tag content into a path and optional filters.
fn parse_interpolation(
    content: &str,
) -> Result<(TemplatePath, Vec<TemplateFilter>), TemplateError> {
    let parts: Vec<&str> = content.splitn(2, '|').collect();
    let path = TemplatePath::new(parts[0].trim());
    let mut filters = Vec::new();

    if parts.len() > 1 {
        // Could have chained filters: `field | upper | trim`
        let filter_chain = parts[1];
        for filter_str in filter_chain.split('|') {
            let f = parse_filter(filter_str.trim())?;
            filters.push(f);
        }
    }

    Ok((path, filters))
}

/// Parse a filter name (with optional argument).
fn parse_filter(s: &str) -> Result<TemplateFilter, TemplateError> {
    // Check for filters with arguments: `default "val"`, `truncate 50`
    let (name, arg) = if let Some(idx) = s.find(' ') {
        (&s[..idx], Some(s[idx + 1..].trim()))
    } else {
        (s, None)
    };

    match name {
        "upper" => Ok(TemplateFilter::Upper),
        "lower" => Ok(TemplateFilter::Lower),
        "trim" => Ok(TemplateFilter::Trim),
        "length" => Ok(TemplateFilter::Length),
        "json" => Ok(TemplateFilter::Json),
        "url_encode" => Ok(TemplateFilter::UrlEncode),
        "html_escape" => Ok(TemplateFilter::HtmlEscape),
        "capitalize" => Ok(TemplateFilter::Capitalize),
        "reverse" => Ok(TemplateFilter::Reverse),
        "base64" => Ok(TemplateFilter::Base64),
        "base64_decode" => Ok(TemplateFilter::Base64Decode),
        "strip_tags" => Ok(TemplateFilter::StripTags),
        "default" => {
            let val = arg
                .map(|a| a.trim_matches('"').to_string())
                .unwrap_or_default();
            Ok(TemplateFilter::Default(val))
        }
        "truncate" => {
            let n: usize = arg.and_then(|a| a.parse().ok()).unwrap_or(80);
            Ok(TemplateFilter::Truncate(n))
        }
        "replace" => {
            // `replace "old" "new"`
            if let Some(a) = arg {
                let parts = parse_two_string_args(a);
                Ok(TemplateFilter::Replace(parts.0, parts.1))
            } else {
                Ok(TemplateFilter::Replace(String::new(), String::new()))
            }
        }
        "pad_left" => {
            let n: usize = arg.and_then(|a| a.parse().ok()).unwrap_or(0);
            Ok(TemplateFilter::PadLeft(n))
        }
        "pad_right" => {
            let n: usize = arg.and_then(|a| a.parse().ok()).unwrap_or(0);
            Ok(TemplateFilter::PadRight(n))
        }
        "repeat" => {
            let n: usize = arg.and_then(|a| a.parse().ok()).unwrap_or(1);
            Ok(TemplateFilter::Repeat(n))
        }
        "split" => {
            let sep = arg
                .map(|a| a.trim_matches('"').to_string())
                .unwrap_or_default();
            Ok(TemplateFilter::Split(sep))
        }
        "join" => {
            let sep = arg
                .map(|a| a.trim_matches('"').to_string())
                .unwrap_or_default();
            Ok(TemplateFilter::Join(sep))
        }
        "pluralize" => {
            if let Some(a) = arg {
                let parts = parse_two_string_args(a);
                Ok(TemplateFilter::Pluralize(parts.0, parts.1))
            } else {
                Ok(TemplateFilter::Pluralize("".into(), "s".into()))
            }
        }
        "indent" => {
            let n: usize = arg.and_then(|a| a.parse().ok()).unwrap_or(2);
            Ok(TemplateFilter::Indent(n))
        }
        _ => Err(TemplateError::ParseError {
            message: format!("unknown filter: {name}"),
            offset: 0,
        }),
    }
}

/// Parse two quoted string arguments from `"old" "new"`.
fn parse_two_string_args(s: &str) -> (String, String) {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in s.chars() {
        match ch {
            '"' => {
                if in_quotes {
                    parts.push(std::mem::take(&mut current));
                    in_quotes = false;
                } else {
                    in_quotes = true;
                }
            }
            _ if in_quotes => current.push(ch),
            _ => {}
        }
    }
    let first = parts.first().cloned().unwrap_or_default();
    let second = parts.get(1).cloned().unwrap_or_default();
    (first, second)
}

// ── Rendering ───────────────────────────────────────────────────────────

/// Render a parsed template with the given data.
pub fn render(template: &Template, data: &Value) -> Result<String, TemplateError> {
    let ctx = RenderContext::new(data.clone());
    render_nodes(&template.nodes, &ctx)
}

/// Render a list of nodes.
fn render_nodes(nodes: &[TemplateNode], ctx: &RenderContext) -> Result<String, TemplateError> {
    let mut out = String::new();
    for node in nodes {
        out.push_str(&render_node(node, ctx)?);
    }
    Ok(out)
}

/// Render a single node.
fn render_node(node: &TemplateNode, ctx: &RenderContext) -> Result<String, TemplateError> {
    match node {
        TemplateNode::Literal(s) => Ok(s.clone()),

        TemplateNode::Interpolation { path, filters } => {
            let value = resolve_path(path, ctx);
            let mut s = value_to_string(&value);
            for filter in filters {
                s = apply_filter(&s, &value, filter)?;
            }
            Ok(s)
        }

        TemplateNode::If {
            path,
            body,
            else_body,
        } => {
            let value = resolve_path(path, ctx);
            if is_truthy_template(&value) {
                render_nodes(body, ctx)
            } else {
                render_nodes(else_body, ctx)
            }
        }

        TemplateNode::Unless { path, body } => {
            let value = resolve_path(path, ctx);
            if !is_truthy_template(&value) {
                render_nodes(body, ctx)
            } else {
                Ok(String::new())
            }
        }

        TemplateNode::Each { path, body } => {
            let value = resolve_path(path, ctx);
            match &value {
                Value::Array(arr) => {
                    let mut out = String::new();
                    for (i, item) in arr.iter().enumerate() {
                        let child = ctx.child_for_each(i, item.clone());
                        out.push_str(&render_nodes(body, &child)?);
                    }
                    Ok(out)
                }
                Value::Object(map) => {
                    let mut out = String::new();
                    for (i, (key, val)) in map.iter().enumerate() {
                        // In object iteration, `this` is the value, `@index` is the key
                        let mut child = ctx.child_for_each(i, val.clone());
                        // Store key as a special field
                        child.current = Some(serde_json::json!({
                            "@key": key,
                            "@value": val,
                        }));
                        // Actually, for simplicity, `this` is the value
                        child.current = Some(val.clone());
                        out.push_str(&render_nodes(body, &child)?);
                    }
                    Ok(out)
                }
                _ => Ok(String::new()),
            }
        }
    }
}

/// Resolve a path against a render context.
fn resolve_path(path: &TemplatePath, ctx: &RenderContext) -> Value {
    if path.is_this() {
        return ctx.current.clone().unwrap_or(Value::Null);
    }
    if path.is_index() {
        return ctx
            .index
            .map(|i| Value::Number(i.into()))
            .unwrap_or(Value::Null);
    }

    // Handle `this.field.nested` — strip the `this` prefix and resolve against current
    if path.segments.first().map(|s| s.as_str()) == Some("this") && path.segments.len() > 1 {
        if let Some(ref current) = ctx.current {
            let rest = &path.segments[1..];
            return resolve_value(current, rest);
        }
        return Value::Null;
    }

    // First try resolving against current (for each-loop context)
    if let Some(ref current) = ctx.current {
        if current.is_object() {
            let resolved = resolve_value(current, &path.segments);
            if !resolved.is_null() {
                return resolved;
            }
        }
    }

    // Fall back to root data
    resolve_value(&ctx.data, &path.segments)
}

/// Walk a value by path segments.
fn resolve_value(value: &Value, segments: &[String]) -> Value {
    let mut current = value.clone();
    for seg in segments {
        match &current {
            Value::Object(map) => {
                current = map.get(seg.as_str()).cloned().unwrap_or(Value::Null);
            }
            _ => return Value::Null,
        }
    }
    current
}

/// Convert a JSON value to its string representation for template output.
fn value_to_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value).unwrap_or_default(),
    }
}

/// Check if a value is truthy for template conditionals.
/// Falsy values: null, false, empty string, 0, empty array, empty object.
fn is_truthy_template(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

/// Apply a filter to a string value.
fn apply_filter(
    s: &str,
    _original: &Value,
    filter: &TemplateFilter,
) -> Result<String, TemplateError> {
    match filter {
        TemplateFilter::Upper => Ok(s.to_uppercase()),
        TemplateFilter::Lower => Ok(s.to_lowercase()),
        TemplateFilter::Trim => Ok(s.trim().to_string()),
        TemplateFilter::Length => Ok(s.len().to_string()),
        TemplateFilter::Default(d) => {
            if s.is_empty() {
                Ok(d.clone())
            } else {
                Ok(s.to_string())
            }
        }
        TemplateFilter::Json => {
            // Wrap as JSON string
            Ok(serde_json::to_string(&Value::String(s.to_string()))
                .unwrap_or_else(|_| format!("\"{s}\"")))
        }
        TemplateFilter::UrlEncode => Ok(url_encode(s)),
        TemplateFilter::HtmlEscape => Ok(html_escape(s)),
        TemplateFilter::Capitalize => {
            let mut chars = s.chars();
            match chars.next() {
                None => Ok(String::new()),
                Some(c) => {
                    let upper: String = c.to_uppercase().collect();
                    Ok(format!("{upper}{}", chars.as_str()))
                }
            }
        }
        TemplateFilter::Truncate(n) => {
            if s.len() <= *n {
                Ok(s.to_string())
            } else {
                let truncated: String = s.chars().take(*n).collect();
                Ok(format!("{truncated}..."))
            }
        }
        TemplateFilter::Replace(old, new) => Ok(s.replace(old.as_str(), new.as_str())),
        TemplateFilter::PadLeft(n) => Ok(format!("{s:>width$}", width = *n)),
        TemplateFilter::PadRight(n) => Ok(format!("{s:<width$}", width = *n)),
        TemplateFilter::Repeat(n) => Ok(s.repeat(*n)),
        TemplateFilter::Reverse => Ok(s.chars().rev().collect()),
        TemplateFilter::Split(sep) => {
            let parts: Vec<&str> = s.split(sep.as_str()).collect();
            Ok(serde_json::to_string(&parts).unwrap_or_default())
        }
        TemplateFilter::Join(sep) => {
            // If the string looks like a JSON array, join its elements
            if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(s) {
                let strs: Vec<String> = arr.iter().map(value_to_string).collect();
                Ok(strs.join(sep.as_str()))
            } else {
                Ok(s.to_string())
            }
        }
        TemplateFilter::Base64 => {
            use base64::Engine;
            Ok(base64::engine::general_purpose::STANDARD.encode(s.as_bytes()))
        }
        TemplateFilter::Base64Decode => {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(s.as_bytes()) {
                Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).to_string()),
                Err(_) => Err(TemplateError::RenderError("invalid base64 input".into())),
            }
        }
        TemplateFilter::StripTags => Ok(strip_html_tags(s)),
        TemplateFilter::Pluralize(singular, plural) => {
            if s == "1" {
                Ok(singular.clone())
            } else {
                Ok(plural.clone())
            }
        }
        TemplateFilter::Indent(n) => {
            let prefix = " ".repeat(*n);
            let indented: Vec<String> = s.lines().map(|line| format!("{prefix}{line}")).collect();
            Ok(indented.join("\n"))
        }
    }
}

/// Simple URL encoding.
fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push_str(&format!("{byte:02X}"));
            }
        }
    }
    out
}

/// HTML escape special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Strip HTML tags from a string.
fn strip_html_tags(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for ch in s.chars() {
        match ch {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Simple interpolation ──

    #[test]
    fn interpolate_simple_field() {
        let t = parse_template("Hello, {{name}}!").unwrap();
        let data = json!({"name": "Alice"});
        assert_eq!(render(&t, &data).unwrap(), "Hello, Alice!");
    }

    #[test]
    fn interpolate_number() {
        let t = parse_template("Count: {{count}}").unwrap();
        let data = json!({"count": 42});
        assert_eq!(render(&t, &data).unwrap(), "Count: 42");
    }

    #[test]
    fn interpolate_bool() {
        let t = parse_template("Active: {{active}}").unwrap();
        let data = json!({"active": true});
        assert_eq!(render(&t, &data).unwrap(), "Active: true");
    }

    #[test]
    fn interpolate_missing_field() {
        let t = parse_template("Name: {{name}}").unwrap();
        let data = json!({"age": 30});
        assert_eq!(render(&t, &data).unwrap(), "Name: ");
    }

    #[test]
    fn interpolate_null() {
        let t = parse_template("Val: {{val}}").unwrap();
        let data = json!({"val": null});
        assert_eq!(render(&t, &data).unwrap(), "Val: ");
    }

    // ── Nested path interpolation ──

    #[test]
    fn interpolate_nested_path() {
        let t = parse_template("{{user.name}}").unwrap();
        let data = json!({"user": {"name": "Bob"}});
        assert_eq!(render(&t, &data).unwrap(), "Bob");
    }

    #[test]
    fn interpolate_deeply_nested() {
        let t = parse_template("{{a.b.c.d}}").unwrap();
        let data = json!({"a": {"b": {"c": {"d": "deep"}}}});
        assert_eq!(render(&t, &data).unwrap(), "deep");
    }

    #[test]
    fn interpolate_nested_missing() {
        let t = parse_template("{{a.b.c}}").unwrap();
        let data = json!({"a": {"x": 1}});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    // ── Conditionals ──

    #[test]
    fn if_true() {
        let t = parse_template("{{#if active}}ON{{/if}}").unwrap();
        let data = json!({"active": true});
        assert_eq!(render(&t, &data).unwrap(), "ON");
    }

    #[test]
    fn if_false() {
        let t = parse_template("{{#if active}}ON{{/if}}").unwrap();
        let data = json!({"active": false});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    #[test]
    fn if_null() {
        let t = parse_template("{{#if val}}YES{{/if}}").unwrap();
        let data = json!({"val": null});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    #[test]
    fn if_truthy_string() {
        let t = parse_template("{{#if name}}Hi{{/if}}").unwrap();
        let data = json!({"name": "x"});
        assert_eq!(render(&t, &data).unwrap(), "Hi");
    }

    #[test]
    fn if_falsy_empty_string() {
        let t = parse_template("{{#if name}}Hi{{/if}}").unwrap();
        let data = json!({"name": ""});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    #[test]
    fn if_truthy_number() {
        let t = parse_template("{{#if n}}YES{{/if}}").unwrap();
        let data = json!({"n": 1});
        assert_eq!(render(&t, &data).unwrap(), "YES");
    }

    #[test]
    fn if_falsy_zero() {
        let t = parse_template("{{#if n}}YES{{/if}}").unwrap();
        let data = json!({"n": 0});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    #[test]
    fn if_truthy_array() {
        let t = parse_template("{{#if items}}HAS{{/if}}").unwrap();
        let data = json!({"items": [1]});
        assert_eq!(render(&t, &data).unwrap(), "HAS");
    }

    #[test]
    fn if_falsy_empty_array() {
        let t = parse_template("{{#if items}}HAS{{/if}}").unwrap();
        let data = json!({"items": []});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    #[test]
    fn if_else_true() {
        let t = parse_template("{{#if on}}YES{{else}}NO{{/if}}").unwrap();
        let data = json!({"on": true});
        assert_eq!(render(&t, &data).unwrap(), "YES");
    }

    #[test]
    fn if_else_false() {
        let t = parse_template("{{#if on}}YES{{else}}NO{{/if}}").unwrap();
        let data = json!({"on": false});
        assert_eq!(render(&t, &data).unwrap(), "NO");
    }

    // ── Unless ──

    #[test]
    fn unless_false() {
        let t = parse_template("{{#unless disabled}}ENABLED{{/unless}}").unwrap();
        let data = json!({"disabled": false});
        assert_eq!(render(&t, &data).unwrap(), "ENABLED");
    }

    #[test]
    fn unless_true() {
        let t = parse_template("{{#unless disabled}}ENABLED{{/unless}}").unwrap();
        let data = json!({"disabled": true});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    #[test]
    fn unless_null() {
        let t = parse_template("{{#unless val}}MISSING{{/unless}}").unwrap();
        let data = json!({"val": null});
        assert_eq!(render(&t, &data).unwrap(), "MISSING");
    }

    #[test]
    fn unless_missing_field() {
        let t = parse_template("{{#unless x}}DEFAULT{{/unless}}").unwrap();
        let data = json!({});
        assert_eq!(render(&t, &data).unwrap(), "DEFAULT");
    }

    // ── Each loops ──

    #[test]
    fn each_array() {
        let t = parse_template("{{#each items}}[{{this}}]{{/each}}").unwrap();
        let data = json!({"items": [1, 2, 3]});
        assert_eq!(render(&t, &data).unwrap(), "[1][2][3]");
    }

    #[test]
    fn each_with_index() {
        let t = parse_template("{{#each items}}{{@index}}:{{this}} {{/each}}").unwrap();
        let data = json!({"items": ["a", "b"]});
        assert_eq!(render(&t, &data).unwrap(), "0:a 1:b ");
    }

    #[test]
    fn each_empty_array() {
        let t = parse_template("{{#each items}}X{{/each}}").unwrap();
        let data = json!({"items": []});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    #[test]
    fn each_null() {
        let t = parse_template("{{#each items}}X{{/each}}").unwrap();
        let data = json!({"items": null});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    #[test]
    fn each_missing() {
        let t = parse_template("{{#each items}}X{{/each}}").unwrap();
        let data = json!({});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    #[test]
    fn each_objects() {
        let t = parse_template("{{#each users}}{{this.name}} {{/each}}").unwrap();
        let data = json!({"users": [{"name": "A"}, {"name": "B"}]});
        // `this` is the object; `this.name` should resolve via the object
        // Actually our resolve_path checks current first, so `name` alone should work too
        assert_eq!(render(&t, &data).unwrap(), "A B ");
    }

    #[test]
    fn each_field_of_items() {
        let t = parse_template("{{#each users}}{{name}} {{/each}}").unwrap();
        let data = json!({"users": [{"name": "X"}, {"name": "Y"}]});
        assert_eq!(render(&t, &data).unwrap(), "X Y ");
    }

    #[test]
    fn each_strings() {
        let t = parse_template("{{#each tags}}#{{this}} {{/each}}").unwrap();
        let data = json!({"tags": ["rust", "fcp"]});
        assert_eq!(render(&t, &data).unwrap(), "#rust #fcp ");
    }

    // ── Pipe filters ──

    #[test]
    fn filter_upper() {
        let t = parse_template("{{name | upper}}").unwrap();
        let data = json!({"name": "alice"});
        assert_eq!(render(&t, &data).unwrap(), "ALICE");
    }

    #[test]
    fn filter_lower() {
        let t = parse_template("{{name | lower}}").unwrap();
        let data = json!({"name": "ALICE"});
        assert_eq!(render(&t, &data).unwrap(), "alice");
    }

    #[test]
    fn filter_trim() {
        let t = parse_template("[{{val | trim}}]").unwrap();
        let data = json!({"val": "  hello  "});
        assert_eq!(render(&t, &data).unwrap(), "[hello]");
    }

    #[test]
    fn filter_length() {
        let t = parse_template("{{name | length}}").unwrap();
        let data = json!({"name": "hello"});
        assert_eq!(render(&t, &data).unwrap(), "5");
    }

    #[test]
    fn filter_default_present() {
        let t = parse_template("{{name | default \"nobody\"}}").unwrap();
        let data = json!({"name": "alice"});
        assert_eq!(render(&t, &data).unwrap(), "alice");
    }

    #[test]
    fn filter_default_missing() {
        let t = parse_template("{{name | default \"nobody\"}}").unwrap();
        let data = json!({});
        assert_eq!(render(&t, &data).unwrap(), "nobody");
    }

    #[test]
    fn filter_default_null() {
        let t = parse_template("{{name | default \"N/A\"}}").unwrap();
        let data = json!({"name": null});
        assert_eq!(render(&t, &data).unwrap(), "N/A");
    }

    #[test]
    fn filter_capitalize() {
        let t = parse_template("{{word | capitalize}}").unwrap();
        let data = json!({"word": "hello"});
        assert_eq!(render(&t, &data).unwrap(), "Hello");
    }

    #[test]
    fn filter_truncate() {
        let t = parse_template("{{text | truncate 5}}").unwrap();
        let data = json!({"text": "hello world"});
        assert_eq!(render(&t, &data).unwrap(), "hello...");
    }

    #[test]
    fn filter_truncate_short() {
        let t = parse_template("{{text | truncate 20}}").unwrap();
        let data = json!({"text": "hi"});
        assert_eq!(render(&t, &data).unwrap(), "hi");
    }

    #[test]
    fn filter_reverse() {
        let t = parse_template("{{text | reverse}}").unwrap();
        let data = json!({"text": "abc"});
        assert_eq!(render(&t, &data).unwrap(), "cba");
    }

    #[test]
    fn filter_html_escape() {
        let t = parse_template("{{html | html_escape}}").unwrap();
        let data = json!({"html": "<b>hi</b>"});
        assert_eq!(render(&t, &data).unwrap(), "&lt;b&gt;hi&lt;/b&gt;");
    }

    #[test]
    fn filter_url_encode() {
        let t = parse_template("{{q | url_encode}}").unwrap();
        let data = json!({"q": "hello world"});
        assert_eq!(render(&t, &data).unwrap(), "hello+world");
    }

    #[test]
    fn filter_chained() {
        let t = parse_template("{{name | trim | upper}}").unwrap();
        let data = json!({"name": "  alice  "});
        assert_eq!(render(&t, &data).unwrap(), "ALICE");
    }

    #[test]
    fn filter_strip_tags() {
        let t = parse_template("{{html | strip_tags}}").unwrap();
        let data = json!({"html": "<p>Hello <b>world</b></p>"});
        assert_eq!(render(&t, &data).unwrap(), "Hello world");
    }

    #[test]
    fn filter_repeat() {
        let t = parse_template("{{ch | repeat 3}}").unwrap();
        let data = json!({"ch": "ab"});
        assert_eq!(render(&t, &data).unwrap(), "ababab");
    }

    #[test]
    fn filter_replace() {
        let t = parse_template("{{text | replace \"old\" \"new\"}}").unwrap();
        let data = json!({"text": "old data old"});
        assert_eq!(render(&t, &data).unwrap(), "new data new");
    }

    #[test]
    fn filter_pad_left() {
        let t = parse_template("[{{n | pad_left 5}}]").unwrap();
        let data = json!({"n": "42"});
        assert_eq!(render(&t, &data).unwrap(), "[   42]");
    }

    #[test]
    fn filter_pad_right() {
        let t = parse_template("[{{n | pad_right 5}}]").unwrap();
        let data = json!({"n": "42"});
        assert_eq!(render(&t, &data).unwrap(), "[42   ]");
    }

    // ── Nested blocks ──

    #[test]
    fn nested_if_inside_each() {
        let t = parse_template("{{#each items}}{{#if active}}*{{/if}}{{name}} {{/each}}").unwrap();
        let data = json!({"items": [
            {"name": "a", "active": true},
            {"name": "b", "active": false},
            {"name": "c", "active": true}
        ]});
        assert_eq!(render(&t, &data).unwrap(), "*a b *c ");
    }

    #[test]
    fn nested_each() {
        let t =
            parse_template("{{#each groups}}{{#each items}}{{this}}{{/each}};{{/each}}").unwrap();
        let data = json!({"groups": [
            {"items": [1, 2]},
            {"items": [3]}
        ]});
        assert_eq!(render(&t, &data).unwrap(), "12;3;");
    }

    #[test]
    fn if_with_interpolation() {
        let t = parse_template("{{#if name}}Hello {{name}}{{/if}}").unwrap();
        let data = json!({"name": "World"});
        assert_eq!(render(&t, &data).unwrap(), "Hello World");
    }

    // ── Edge cases ──

    #[test]
    fn no_tags() {
        let t = parse_template("plain text").unwrap();
        let data = json!({});
        assert_eq!(render(&t, &data).unwrap(), "plain text");
    }

    #[test]
    fn empty_template() {
        let t = parse_template("").unwrap();
        let data = json!({});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    #[test]
    fn escaped_braces() {
        let t = parse_template("\\{{not a tag}}").unwrap();
        let data = json!({});
        assert_eq!(render(&t, &data).unwrap(), "{{not a tag}}");
    }

    #[test]
    fn multiple_interpolations() {
        let t = parse_template("{{first}} {{last}}").unwrap();
        let data = json!({"first": "John", "last": "Doe"});
        assert_eq!(render(&t, &data).unwrap(), "John Doe");
    }

    #[test]
    fn empty_data() {
        let t = parse_template("{{a}}{{b}}{{c}}").unwrap();
        let data = json!({});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    #[test]
    fn truthy_object() {
        let t = parse_template("{{#if cfg}}YES{{/if}}").unwrap();
        let data = json!({"cfg": {"key": "val"}});
        assert_eq!(render(&t, &data).unwrap(), "YES");
    }

    #[test]
    fn falsy_empty_object() {
        let t = parse_template("{{#if cfg}}YES{{/if}}").unwrap();
        let data = json!({"cfg": {}});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    #[test]
    fn array_value_rendered_as_json() {
        let t = parse_template("{{items}}").unwrap();
        let data = json!({"items": [1, 2, 3]});
        let result = render(&t, &data).unwrap();
        assert_eq!(result, "[1,2,3]");
    }

    #[test]
    fn object_value_rendered_as_json() {
        let t = parse_template("{{cfg}}").unwrap();
        let data = json!({"cfg": {"a": 1}});
        let result = render(&t, &data).unwrap();
        assert_eq!(result, "{\"a\":1}");
    }

    // ── Error cases ──

    #[test]
    fn error_unclosed_tag() {
        let err = parse_template("Hello {{name").unwrap_err();
        assert!(matches!(err, TemplateError::ParseError { .. }));
    }

    #[test]
    fn error_unclosed_if() {
        let err = parse_template("{{#if x}}hello").unwrap_err();
        assert!(matches!(err, TemplateError::UnclosedBlock(_)));
    }

    #[test]
    fn error_unclosed_each() {
        let err = parse_template("{{#each x}}hi").unwrap_err();
        assert!(matches!(err, TemplateError::UnclosedBlock(_)));
    }

    #[test]
    fn error_unclosed_unless() {
        let err = parse_template("{{#unless x}}hi").unwrap_err();
        assert!(matches!(err, TemplateError::UnclosedBlock(_)));
    }

    #[test]
    fn error_unknown_filter() {
        let err = parse_template("{{x | bogus}}").unwrap_err();
        assert!(matches!(err, TemplateError::ParseError { .. }));
    }

    #[test]
    fn error_display_parse() {
        let e = TemplateError::ParseError {
            message: "bad".into(),
            offset: 5,
        };
        assert_eq!(format!("{e}"), "parse error at offset 5: bad");
    }

    #[test]
    fn error_display_unclosed() {
        let e = TemplateError::UnclosedBlock("if".into());
        assert_eq!(format!("{e}"), "unclosed block: {{#if}}");
    }

    #[test]
    fn error_display_mismatched() {
        let e = TemplateError::MismatchedBlock {
            expected: "if".into(),
            found: "each".into(),
        };
        assert_eq!(
            format!("{e}"),
            "mismatched block: expected {{/if}} but found {{/each}}"
        );
    }

    #[test]
    fn error_display_render() {
        let e = TemplateError::RenderError("oops".into());
        assert_eq!(format!("{e}"), "render error: oops");
    }

    // ── Render context ──

    #[test]
    fn render_context_new() {
        let ctx = RenderContext::new(json!({"a": 1}));
        assert!(ctx.index.is_none());
        assert!(ctx.current.is_none());
        assert_eq!(ctx.data, json!({"a": 1}));
    }

    #[test]
    fn render_context_child() {
        let ctx = RenderContext::new(json!({"root": true}));
        let child = ctx.child_for_each(2, json!("item"));
        assert_eq!(child.index, Some(2));
        assert_eq!(child.current, Some(json!("item")));
        assert_eq!(child.data, json!({"root": true}));
    }

    // ── Template path helpers ──

    #[test]
    fn path_is_this() {
        assert!(TemplatePath::new("this").is_this());
        assert!(!TemplatePath::new("that").is_this());
    }

    #[test]
    fn path_is_index() {
        assert!(TemplatePath::new("@index").is_index());
        assert!(!TemplatePath::new("index").is_index());
    }

    // ── Value stringification ──

    #[test]
    fn value_to_string_null() {
        assert_eq!(value_to_string(&Value::Null), "");
    }

    #[test]
    fn value_to_string_bool() {
        assert_eq!(value_to_string(&json!(true)), "true");
    }

    #[test]
    fn value_to_string_number() {
        assert_eq!(value_to_string(&json!(42)), "42");
    }

    #[test]
    fn value_to_string_string() {
        assert_eq!(value_to_string(&json!("hi")), "hi");
    }

    // ── Truthiness ──

    #[test]
    fn truthy_values() {
        assert!(is_truthy_template(&json!(true)));
        assert!(is_truthy_template(&json!(1)));
        assert!(is_truthy_template(&json!("x")));
        assert!(is_truthy_template(&json!([1])));
        assert!(is_truthy_template(&json!({"a": 1})));
    }

    #[test]
    fn falsy_values() {
        assert!(!is_truthy_template(&json!(null)));
        assert!(!is_truthy_template(&json!(false)));
        assert!(!is_truthy_template(&json!(0)));
        assert!(!is_truthy_template(&json!("")));
        assert!(!is_truthy_template(&json!([])));
        assert!(!is_truthy_template(&json!({})));
    }

    // ── Complex integration tests ──

    #[test]
    fn complex_user_profile() {
        let t = parse_template(concat!(
            "Name: {{user.name | upper}}\n",
            "{{#if user.email}}Email: {{user.email}}{{/if}}\n",
            "{{#unless user.verified}}(unverified){{/unless}}"
        ))
        .unwrap();
        let data = json!({
            "user": {
                "name": "alice",
                "email": "alice@example.com",
                "verified": false
            }
        });
        assert_eq!(
            render(&t, &data).unwrap(),
            "Name: ALICE\nEmail: alice@example.com\n(unverified)"
        );
    }

    #[test]
    fn complex_list_rendering() {
        let t = parse_template("Items:\n{{#each items}}- {{this | upper}}\n{{/each}}").unwrap();
        let data = json!({"items": ["apple", "banana"]});
        assert_eq!(render(&t, &data).unwrap(), "Items:\n- APPLE\n- BANANA\n");
    }

    #[test]
    fn complex_conditional_list() {
        let t = parse_template(
            "{{#if items}}Found: {{#each items}}{{this}} {{/each}}{{else}}None{{/if}}",
        )
        .unwrap();
        let data = json!({"items": ["x", "y"]});
        assert_eq!(render(&t, &data).unwrap(), "Found: x y ");
    }

    #[test]
    fn complex_conditional_list_empty() {
        let t = parse_template(
            "{{#if items}}Found: {{#each items}}{{this}} {{/each}}{{else}}None{{/if}}",
        )
        .unwrap();
        let data = json!({"items": []});
        assert_eq!(render(&t, &data).unwrap(), "None");
    }

    #[test]
    fn filter_json() {
        let t = parse_template("{{name | json}}").unwrap();
        let data = json!({"name": "hello \"world\""});
        let result = render(&t, &data).unwrap();
        assert_eq!(result, "\"hello \\\"world\\\"\"");
    }

    #[test]
    fn filter_indent() {
        let t = parse_template("{{text | indent 4}}").unwrap();
        let data = json!({"text": "a\nb"});
        assert_eq!(render(&t, &data).unwrap(), "    a\n    b");
    }

    #[test]
    fn filter_pluralize_one() {
        let t = parse_template("{{count | pluralize \"item\" \"items\"}}").unwrap();
        let data = json!({"count": 1});
        assert_eq!(render(&t, &data).unwrap(), "item");
    }

    #[test]
    fn filter_pluralize_many() {
        let t = parse_template("{{count | pluralize \"item\" \"items\"}}").unwrap();
        let data = json!({"count": 5});
        assert_eq!(render(&t, &data).unwrap(), "items");
    }

    #[test]
    fn whitespace_in_tags() {
        let t = parse_template("{{ name }}").unwrap();
        let data = json!({"name": "X"});
        assert_eq!(render(&t, &data).unwrap(), "X");
    }

    #[test]
    fn each_single_item() {
        let t = parse_template("{{#each items}}{{this}}{{/each}}").unwrap();
        let data = json!({"items": ["only"]});
        assert_eq!(render(&t, &data).unwrap(), "only");
    }

    #[test]
    fn nested_unless_in_each() {
        let t = parse_template("{{#each items}}{{#unless disabled}}{{name}}{{/unless}} {{/each}}")
            .unwrap();
        let data = json!({"items": [
            {"name": "a", "disabled": false},
            {"name": "b", "disabled": true}
        ]});
        assert_eq!(render(&t, &data).unwrap(), "a  ");
    }

    #[test]
    fn resolve_root_data_in_each() {
        let t = parse_template("{{#each items}}{{title}}: {{this}} {{/each}}").unwrap();
        let data = json!({"title": "T", "items": [1, 2]});
        assert_eq!(render(&t, &data).unwrap(), "T: 1 T: 2 ");
    }

    #[test]
    fn filter_base64_encode() {
        let t = parse_template("{{text | base64}}").unwrap();
        let data = json!({"text": "hello"});
        assert_eq!(render(&t, &data).unwrap(), "aGVsbG8=");
    }

    #[test]
    fn filter_base64_decode() {
        let t = parse_template("{{encoded | base64_decode}}").unwrap();
        let data = json!({"encoded": "aGVsbG8="});
        assert_eq!(render(&t, &data).unwrap(), "hello");
    }

    #[test]
    fn filter_capitalize_empty() {
        let t = parse_template("{{x | capitalize}}").unwrap();
        let data = json!({"x": ""});
        assert_eq!(render(&t, &data).unwrap(), "");
    }

    #[test]
    fn each_with_nested_path() {
        let t = parse_template("{{#each data.items}}{{this}} {{/each}}").unwrap();
        let data = json!({"data": {"items": ["a", "b"]}});
        assert_eq!(render(&t, &data).unwrap(), "a b ");
    }

    #[test]
    fn if_with_nested_path() {
        let t = parse_template("{{#if config.enabled}}ON{{/if}}").unwrap();
        let data = json!({"config": {"enabled": true}});
        assert_eq!(render(&t, &data).unwrap(), "ON");
    }

    #[test]
    fn unless_with_nested_path() {
        let t = parse_template("{{#unless config.enabled}}OFF{{/unless}}").unwrap();
        let data = json!({"config": {"enabled": false}});
        assert_eq!(render(&t, &data).unwrap(), "OFF");
    }
}
