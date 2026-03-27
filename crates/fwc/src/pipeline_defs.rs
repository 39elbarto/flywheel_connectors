//! Named multi-step pipeline definitions in TOML.
//!
//! Parses pipeline definitions from TOML files, validates them, plans
//! execution waves, resolves template expressions, and formats output
//! in TOON format.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Errors ────────────────────────────────────────────────────────────

/// Errors during pipeline definition parsing and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError {
    /// TOML syntax error.
    TomlParse(String),
    /// Missing required field.
    MissingField(String),
    /// Invalid step reference.
    InvalidStepRef { step_id: String, field: String },
    /// Dependency cycle detected.
    CycleDetected { step_ids: Vec<String> },
    /// Unknown dependency reference.
    UnknownDependency { step_id: String, dependency: String },
    /// Duplicate step ID.
    DuplicateStepId(String),
    /// Invalid template expression.
    InvalidTemplate(String),
    /// Invalid parameter type.
    InvalidParamType(String),
    /// No steps defined.
    EmptyPipeline,
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TomlParse(msg) => write!(f, "TOML parse error: {msg}"),
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::InvalidStepRef { step_id, field } => {
                write!(f, "step '{step_id}': invalid reference in '{field}'")
            }
            Self::CycleDetected { step_ids } => {
                write!(f, "dependency cycle: {}", step_ids.join(", "))
            }
            Self::UnknownDependency {
                step_id,
                dependency,
            } => write!(f, "step '{step_id}' depends on unknown step '{dependency}'"),
            Self::DuplicateStepId(id) => write!(f, "duplicate step id: '{id}'"),
            Self::InvalidTemplate(expr) => write!(f, "invalid template expression: {expr}"),
            Self::InvalidParamType(t) => write!(f, "invalid parameter type: {t}"),
            Self::EmptyPipeline => f.write_str("pipeline has no steps"),
        }
    }
}

// ── Parameter definitions ─────────────────────────────────────────────

/// Type of a pipeline parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamType {
    String,
    Number,
    Bool,
}

/// A pipeline parameter definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamDef {
    /// Parameter type.
    #[serde(rename = "type")]
    pub param_type: ParamType,
    /// Whether this parameter is required.
    #[serde(default)]
    pub required: bool,
    /// Default value (if not required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<Value>,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ── On-error mode ─────────────────────────────────────────────────────

/// What to do when a step fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    Abort,
    Skip,
    Retry,
}

impl Default for OnError {
    fn default() -> Self {
        Self::Abort
    }
}

// ── Pipeline step ─────────────────────────────────────────────────────

/// A single step in a pipeline definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStep {
    /// Unique step identifier.
    pub id: String,
    /// Operation in connector.operation format.
    pub operation: String,
    /// Input payload (may contain template expressions).
    #[serde(default)]
    pub input: Value,
    /// Steps this step depends on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    /// Optional condition expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// Error handling mode.
    #[serde(default)]
    pub on_error: OnError,
    /// Timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

// ── Pipeline definition ───────────────────────────────────────────────

/// A complete pipeline definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineDef {
    /// Pipeline name.
    pub name: String,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Pipeline version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Pipeline steps.
    pub steps: Vec<PipelineStep>,
    /// Parameter definitions.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub params: HashMap<String, ParamDef>,
}

// ── Validation ────────────────────────────────────────────────────────

/// Result of validating a pipeline definition.
#[derive(Debug, Clone)]
pub struct PipelineValidation {
    /// Whether the pipeline is valid (no errors).
    pub valid: bool,
    /// Warning messages.
    pub warnings: Vec<String>,
    /// Error messages.
    pub errors: Vec<String>,
}

/// Validate a pipeline definition for structural correctness.
pub fn validate_pipeline(def: &PipelineDef) -> PipelineValidation {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    if def.steps.is_empty() {
        errors.push("pipeline has no steps".to_owned());
    }

    // Check for duplicate step IDs.
    let mut seen_ids: BTreeSet<String> = BTreeSet::new();
    for step in &def.steps {
        if !seen_ids.insert(step.id.clone()) {
            errors.push(format!("duplicate step id: '{}'", step.id));
        }
        if step.id.is_empty() {
            errors.push("step has empty id".to_owned());
        }
        if step.operation.is_empty() {
            errors.push(format!("step '{}': operation is empty", step.id));
        }
    }

    // Check dependency references.
    for step in &def.steps {
        for dep in &step.depends_on {
            if !seen_ids.contains(dep.as_str()) {
                errors.push(format!(
                    "step '{}' depends on unknown step '{dep}'",
                    step.id
                ));
            }
            if dep == &step.id {
                errors.push(format!("step '{}' depends on itself", step.id));
            }
        }
    }

    // Check for cycles.
    if let Err(e) = check_step_cycles(&def.steps) {
        errors.push(e.to_string());
    }

    // Check for unused parameters.
    let used_params = collect_template_params_owned(&def.steps);
    for name in def.params.keys() {
        if !used_params.contains(name) {
            warnings.push(format!("parameter '{name}' is defined but never used"));
        }
    }

    // Check for referenced but undefined parameters.
    for param_ref in &used_params {
        if !def.params.contains_key(param_ref) {
            warnings.push(format!(
                "template references parameter '{param_ref}' which is not defined"
            ));
        }
    }

    // Check required params without defaults.
    for (name, param) in &def.params {
        if param.required && param.default_value.is_some() {
            warnings.push(format!(
                "parameter '{name}' is marked required but has a default value"
            ));
        }
    }

    let valid = errors.is_empty();

    PipelineValidation {
        valid,
        warnings,
        errors,
    }
}

/// Collect all parameter names referenced via `{{params.X}}` templates.
fn collect_template_params_owned(steps: &[PipelineStep]) -> BTreeSet<String> {
    let mut params = BTreeSet::new();
    for step in steps {
        let json_str = serde_json::to_string(&step.input).unwrap_or_default();
        for r in extract_template_refs(&json_str) {
            if let Some(name) = r.strip_prefix("params.") {
                params.insert(name.to_owned());
            }
        }
        if let Some(cond) = &step.condition {
            for r in extract_template_refs(cond) {
                if let Some(name) = r.strip_prefix("params.") {
                    params.insert(name.to_owned());
                }
            }
        }
    }
    params
}

/// Extract all `{{...}}` template references from a string.
fn extract_template_refs(s: &str) -> Vec<&str> {
    let mut refs = Vec::new();
    let mut search = s;
    while let Some(start) = search.find("{{") {
        let rest = &search[start + 2..];
        if let Some(end) = rest.find("}}") {
            let inner = rest[..end].trim();
            refs.push(inner);
            search = &rest[end + 2..];
        } else {
            break;
        }
    }
    refs
}

// ── Cycle detection ───────────────────────────────────────────────────

/// Check for cycles in step dependencies.
fn check_step_cycles(steps: &[PipelineStep]) -> Result<(), PipelineError> {
    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

    for step in steps {
        in_degree.entry(step.id.as_str()).or_insert(0);
        for dep in &step.depends_on {
            *in_degree.entry(step.id.as_str()).or_insert(0) += 1;
            dependents
                .entry(dep.as_str())
                .or_default()
                .push(step.id.as_str());
        }
    }

    let mut queue: VecDeque<&str> = in_degree
        .iter()
        .filter(|(_, deg)| **deg == 0)
        .map(|(&id, _)| id)
        .collect();

    let mut visited = 0;
    while let Some(id) = queue.pop_front() {
        visited += 1;
        if let Some(deps) = dependents.get(id) {
            for &dep_id in deps {
                if let Some(deg) = in_degree.get_mut(dep_id) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(dep_id);
                    }
                }
            }
        }
    }

    if visited < steps.len() {
        let cycle_ids: Vec<String> = in_degree
            .iter()
            .filter(|(_, deg)| **deg > 0)
            .map(|(&id, _)| id.to_owned())
            .collect();
        return Err(PipelineError::CycleDetected {
            step_ids: cycle_ids,
        });
    }

    Ok(())
}

// ── TOML parsing ──────────────────────────────────────────────────────

/// Parse a pipeline definition from a TOML string.
pub fn parse_pipeline_toml(s: &str) -> Result<PipelineDef, PipelineError> {
    let def: PipelineDef =
        toml::from_str(s).map_err(|e| PipelineError::TomlParse(e.to_string()))?;

    if def.name.is_empty() {
        return Err(PipelineError::MissingField("name".to_owned()));
    }

    if def.steps.is_empty() {
        return Err(PipelineError::EmptyPipeline);
    }

    // Check for duplicate step IDs.
    let mut seen = BTreeSet::new();
    for step in &def.steps {
        if !seen.insert(&step.id) {
            return Err(PipelineError::DuplicateStepId(step.id.clone()));
        }
    }

    // Validate dependency references.
    for step in &def.steps {
        for dep in &step.depends_on {
            if !seen.contains(dep) {
                return Err(PipelineError::UnknownDependency {
                    step_id: step.id.clone(),
                    dependency: dep.clone(),
                });
            }
        }
    }

    // Check for cycles.
    check_step_cycles(&def.steps)?;

    Ok(def)
}

// ── Template resolution ───────────────────────────────────────────────

/// Resolve a template expression like `{{params.x}}` or `{{steps.y.output.field}}`.
pub fn resolve_template(
    expr: &str,
    params: &HashMap<String, Value>,
    step_outputs: &HashMap<String, Value>,
) -> Result<Value, String> {
    let mut result = expr.to_owned();
    let mut has_substitution = false;

    // Find all {{...}} patterns and replace them.
    let refs = extract_template_refs(expr);
    for r in &refs {
        let replacement = resolve_single_ref(r, params, step_outputs)?;
        let pattern = format!("{{{{{r}}}}}");
        let replacement_str = match &replacement {
            Value::String(s) => s.clone(),
            other => serde_json::to_string(other).unwrap_or_default(),
        };
        result = result.replace(&pattern, &replacement_str);
        has_substitution = true;
    }

    if has_substitution {
        // Try to parse as JSON; if it fails, return as string.
        match serde_json::from_str(&result) {
            Ok(v) => Ok(v),
            Err(_) => Ok(Value::String(result)),
        }
    } else {
        // No templates found, return as-is.
        Ok(Value::String(expr.to_owned()))
    }
}

/// Resolve a single template reference (without the `{{` `}}` delimiters).
fn resolve_single_ref(
    reference: &str,
    params: &HashMap<String, Value>,
    step_outputs: &HashMap<String, Value>,
) -> Result<Value, String> {
    let reference = reference.trim();

    if let Some(param_name) = reference.strip_prefix("params.") {
        params
            .get(param_name)
            .cloned()
            .ok_or_else(|| format!("parameter '{param_name}' not found"))
    } else if let Some(rest) = reference.strip_prefix("steps.") {
        // Format: steps.<step_id>.output[.field[.subfield...]]
        let parts: Vec<&str> = rest.splitn(3, '.').collect();
        if parts.len() < 2 {
            return Err(format!("invalid step reference: {reference}"));
        }
        let step_id = parts[0];
        if parts[1] != "output" {
            return Err(format!("step reference must use '.output': {reference}"));
        }

        let output = step_outputs
            .get(step_id)
            .ok_or_else(|| format!("step '{step_id}' output not found"))?;

        if parts.len() == 2 {
            Ok(output.clone())
        } else {
            // Navigate into the output value.
            let field_path = parts[2];
            let mut current = output;
            for field in field_path.split('.') {
                current = current.get(field).ok_or_else(|| {
                    format!("field '{field}' not found in step '{step_id}' output")
                })?;
            }
            Ok(current.clone())
        }
    } else {
        Err(format!("unknown template reference: {reference}"))
    }
}

// ── Execution planning ────────────────────────────────────────────────

/// Compute execution waves (parallel groups) from a pipeline definition.
///
/// Returns a list of waves; each wave is a list of step IDs that can
/// execute in parallel.
pub fn plan_execution(def: &PipelineDef) -> Vec<Vec<String>> {
    let mut in_degree: BTreeMap<&str, usize> = BTreeMap::new();
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

    for step in &def.steps {
        in_degree.entry(step.id.as_str()).or_insert(0);
        for dep in &step.depends_on {
            *in_degree.entry(step.id.as_str()).or_insert(0) += 1;
            dependents
                .entry(dep.as_str())
                .or_default()
                .push(step.id.as_str());
        }
    }

    let mut waves = Vec::new();

    loop {
        let ready: Vec<String> = in_degree
            .iter()
            .filter(|(_, deg)| **deg == 0)
            .map(|(&id, _)| id.to_owned())
            .collect();

        if ready.is_empty() {
            break;
        }

        for id in &ready {
            in_degree.remove(id.as_str());
            if let Some(deps) = dependents.get(id.as_str()) {
                for &dep_id in deps {
                    if let Some(deg) = in_degree.get_mut(dep_id) {
                        *deg -= 1;
                    }
                }
            }
        }

        waves.push(ready);
    }

    waves
}

// ── Step result ───────────────────────────────────────────────────────

/// Result of executing a single pipeline step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    /// Step identifier.
    pub step_id: String,
    /// Whether the step succeeded.
    pub success: bool,
    /// Output value (if success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    /// Execution duration.
    pub duration: Duration,
    /// Whether the step was skipped.
    pub skipped: bool,
    /// Error message (if failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result of executing an entire pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    /// Pipeline name.
    pub name: String,
    /// Whether all steps passed.
    pub all_passed: bool,
    /// Individual step results.
    pub step_results: Vec<StepResult>,
    /// Total pipeline duration.
    pub duration: Duration,
    /// Parameters that were used.
    pub params_used: HashMap<String, Value>,
}

// ── TOON formatting ───────────────────────────────────────────────────

/// Format a pipeline execution plan as human-readable TOON output.
pub fn format_pipeline_plan_toon(def: &PipelineDef, plan: &[Vec<String>]) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    let _ = writeln!(out, "Pipeline: {}", def.name);
    if let Some(desc) = &def.description {
        let _ = writeln!(out, "  {desc}");
    }
    if let Some(ver) = &def.version {
        let _ = writeln!(out, "  Version: {ver}");
    }
    let _ = writeln!(out, "  Steps: {}, Waves: {}", def.steps.len(), plan.len());

    if !def.params.is_empty() {
        let _ = writeln!(out, "  Parameters:");
        for (name, param) in &def.params {
            let required = if param.required { " (required)" } else { "" };
            let _ = writeln!(out, "    {name}: {:?}{required}", param.param_type);
        }
    }

    out.push('\n');
    for (i, wave) in plan.iter().enumerate() {
        let _ = writeln!(
            out,
            "  Wave {i} ({} steps): {}",
            wave.len(),
            wave.join(", "),
        );
    }

    out
}

/// Format pipeline execution results as human-readable TOON output.
pub fn format_pipeline_result_toon(result: &PipelineResult) -> String {
    use std::fmt::Write;

    let mut out = String::new();

    let status = if result.all_passed { "PASS" } else { "FAIL" };
    let _ = writeln!(
        out,
        "Pipeline: {} [{status}] ({:.2}s)",
        result.name,
        result.duration.as_secs_f64(),
    );

    let total = result.step_results.len();
    let passed = result.step_results.iter().filter(|s| s.success).count();
    let failed = result
        .step_results
        .iter()
        .filter(|s| !s.success && !s.skipped)
        .count();
    let skipped = result.step_results.iter().filter(|s| s.skipped).count();

    let _ = write!(out, "  {passed}/{total} passed");
    if failed > 0 {
        let _ = write!(out, ", {failed} failed");
    }
    if skipped > 0 {
        let _ = write!(out, ", {skipped} skipped");
    }
    out.push('\n');

    out.push('\n');
    let _ = writeln!(
        out,
        "{:<20}{:<12}{:<10}Details",
        "Step", "Status", "Time"
    );
    out.push_str(&"-".repeat(60));
    out.push('\n');

    for sr in &result.step_results {
        let status_str = if sr.skipped {
            "SKIP"
        } else if sr.success {
            "OK"
        } else {
            "FAIL"
        };
        let time_str = format!("{:.2}s", sr.duration.as_secs_f64());
        let details = if let Some(err) = &sr.error {
            err.clone()
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "{:<20}{:<12}{:<10}{details}",
            sr.step_id, status_str, time_str
        );
    }

    out
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Helper ────────────────────────────────────────────────────

    fn minimal_toml() -> &'static str {
        r#"
name = "test-pipeline"

[[steps]]
id = "s1"
operation = "github.list_repos"

[[steps]]
id = "s2"
operation = "slack.send"
depends_on = ["s1"]
"#
    }

    fn diamond_toml() -> &'static str {
        r#"
name = "diamond"
description = "Diamond dependency pattern"
version = "1.0.0"

[[steps]]
id = "root"
operation = "github.list_repos"

[[steps]]
id = "left"
operation = "slack.notify"
depends_on = ["root"]

[[steps]]
id = "right"
operation = "jira.create"
depends_on = ["root"]

[[steps]]
id = "join"
operation = "datadog.log"
depends_on = ["left", "right"]
"#
    }

    // ── TOML parsing ─────────────────────────────────────────────

    #[test]
    fn parse_minimal_pipeline() {
        let def = parse_pipeline_toml(minimal_toml()).unwrap();
        assert_eq!(def.name, "test-pipeline");
        assert_eq!(def.steps.len(), 2);
        assert_eq!(def.steps[0].id, "s1");
        assert_eq!(def.steps[1].depends_on, vec!["s1"]);
    }

    #[test]
    fn parse_with_description_and_version() {
        let def = parse_pipeline_toml(diamond_toml()).unwrap();
        assert_eq!(
            def.description.as_deref(),
            Some("Diamond dependency pattern")
        );
        assert_eq!(def.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn parse_with_params() {
        let toml = r#"
name = "parameterized"

[params.repo]
type = "string"
required = true
description = "Repository name"

[params.dry_run]
type = "bool"
required = false
default_value = false

[[steps]]
id = "s1"
operation = "github.list_repos"
input = { owner = "{{params.repo}}" }
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        assert_eq!(def.params.len(), 2);
        assert!(def.params.contains_key("repo"));
        assert_eq!(def.params["repo"].param_type, ParamType::String);
        assert!(def.params["repo"].required);
        assert!(!def.params["dry_run"].required);
    }

    #[test]
    fn parse_with_on_error_modes() {
        let toml = r#"
name = "error-modes"

[[steps]]
id = "s1"
operation = "g.o"
on_error = "abort"

[[steps]]
id = "s2"
operation = "g.o"
on_error = "skip"

[[steps]]
id = "s3"
operation = "g.o"
on_error = "retry"
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        assert_eq!(def.steps[0].on_error, OnError::Abort);
        assert_eq!(def.steps[1].on_error, OnError::Skip);
        assert_eq!(def.steps[2].on_error, OnError::Retry);
    }

    #[test]
    fn parse_with_timeout() {
        let toml = r#"
name = "timeout-test"

[[steps]]
id = "s1"
operation = "g.o"
timeout = 30

[[steps]]
id = "s2"
operation = "g.o"
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        assert_eq!(def.steps[0].timeout, Some(30));
        assert!(def.steps[1].timeout.is_none());
    }

    #[test]
    fn parse_with_condition() {
        let toml = r#"
name = "conditional"

[[steps]]
id = "s1"
operation = "g.o"

[[steps]]
id = "s2"
operation = "g.o"
depends_on = ["s1"]
condition = "{{steps.s1.output.count}} > 0"
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        assert_eq!(
            def.steps[1].condition.as_deref(),
            Some("{{steps.s1.output.count}} > 0")
        );
    }

    #[test]
    fn parse_empty_name_error() {
        let toml = r#"
name = ""

[[steps]]
id = "s1"
operation = "g.o"
"#;
        let err = parse_pipeline_toml(toml).unwrap_err();
        assert!(matches!(err, PipelineError::MissingField(_)));
    }

    #[test]
    fn parse_no_steps_error() {
        let toml = r#"
name = "empty"
steps = []
"#;
        let err = parse_pipeline_toml(toml).unwrap_err();
        assert!(matches!(err, PipelineError::EmptyPipeline));
    }

    #[test]
    fn parse_invalid_toml_error() {
        let err = parse_pipeline_toml("not valid toml {{{{").unwrap_err();
        assert!(matches!(err, PipelineError::TomlParse(_)));
    }

    #[test]
    fn parse_duplicate_step_id_error() {
        let toml = r#"
name = "dup"

[[steps]]
id = "s1"
operation = "g.o"

[[steps]]
id = "s1"
operation = "g.p"
"#;
        let err = parse_pipeline_toml(toml).unwrap_err();
        assert!(matches!(err, PipelineError::DuplicateStepId(_)));
    }

    #[test]
    fn parse_unknown_dependency_error() {
        let toml = r#"
name = "bad-dep"

[[steps]]
id = "s1"
operation = "g.o"
depends_on = ["nonexistent"]
"#;
        let err = parse_pipeline_toml(toml).unwrap_err();
        match err {
            PipelineError::UnknownDependency {
                step_id,
                dependency,
            } => {
                assert_eq!(step_id, "s1");
                assert_eq!(dependency, "nonexistent");
            }
            other => panic!("expected UnknownDependency, got {other}"),
        }
    }

    #[test]
    fn parse_cycle_error() {
        let toml = r#"
name = "cycle"

[[steps]]
id = "a"
operation = "g.o"
depends_on = ["b"]

[[steps]]
id = "b"
operation = "g.o"
depends_on = ["a"]
"#;
        let err = parse_pipeline_toml(toml).unwrap_err();
        assert!(matches!(err, PipelineError::CycleDetected { .. }));
    }

    #[test]
    fn parse_self_cycle_error() {
        let toml = r#"
name = "self-cycle"

[[steps]]
id = "a"
operation = "g.o"
depends_on = ["a"]
"#;
        let err = parse_pipeline_toml(toml).unwrap_err();
        assert!(matches!(err, PipelineError::CycleDetected { .. }));
    }

    #[test]
    fn parse_complex_input() {
        let toml = r#"
name = "complex-input"

[[steps]]
id = "s1"
operation = "g.o"

[steps.input]
owner = "myorg"
filters = ["open", "assigned"]
limit = 50
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        assert_eq!(def.steps[0].input["owner"], "myorg");
        assert_eq!(def.steps[0].input["limit"], 50);
    }

    #[test]
    fn parse_default_on_error_is_abort() {
        let toml = r#"
name = "defaults"

[[steps]]
id = "s1"
operation = "g.o"
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        assert_eq!(def.steps[0].on_error, OnError::Abort);
    }

    // ── Param validation ─────────────────────────────────────────

    #[test]
    fn validate_valid_pipeline() {
        let def = parse_pipeline_toml(minimal_toml()).unwrap();
        let v = validate_pipeline(&def);
        assert!(v.valid);
        assert!(v.errors.is_empty());
    }

    #[test]
    fn validate_unused_param_warning() {
        let toml = r#"
name = "unused"

[params.unused_param]
type = "string"
required = false

[[steps]]
id = "s1"
operation = "g.o"
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        let v = validate_pipeline(&def);
        assert!(v.valid);
        assert!(v.warnings.iter().any(|w| w.contains("unused_param")));
    }

    #[test]
    fn validate_required_param_with_default_warning() {
        let toml = r#"
name = "req-default"

[params.x]
type = "string"
required = true
default_value = "hello"

[[steps]]
id = "s1"
operation = "g.o"
input = { val = "{{params.x}}" }
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        let v = validate_pipeline(&def);
        assert!(v.valid);
        assert!(
            v.warnings
                .iter()
                .any(|w| w.contains("required") && w.contains("default"))
        );
    }

    #[test]
    fn validate_undefined_param_ref_warning() {
        let toml = r#"
name = "undef-ref"

[[steps]]
id = "s1"
operation = "g.o"
input = { val = "{{params.nonexistent}}" }
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        let v = validate_pipeline(&def);
        assert!(v.valid); // warnings, not errors
        assert!(v.warnings.iter().any(|w| w.contains("nonexistent")));
    }

    #[test]
    fn validate_empty_steps_error() {
        let def = PipelineDef {
            name: "empty".to_owned(),
            description: None,
            version: None,
            steps: vec![],
            params: HashMap::new(),
        };
        let v = validate_pipeline(&def);
        assert!(!v.valid);
        assert!(v.errors.iter().any(|e| e.contains("no steps")));
    }

    #[test]
    fn validate_duplicate_step_id_error() {
        let def = PipelineDef {
            name: "dup".to_owned(),
            description: None,
            version: None,
            steps: vec![
                PipelineStep {
                    id: "s1".to_owned(),
                    operation: "g.o".to_owned(),
                    input: Value::Null,
                    depends_on: vec![],
                    condition: None,
                    on_error: OnError::Abort,
                    timeout: None,
                },
                PipelineStep {
                    id: "s1".to_owned(),
                    operation: "g.p".to_owned(),
                    input: Value::Null,
                    depends_on: vec![],
                    condition: None,
                    on_error: OnError::Abort,
                    timeout: None,
                },
            ],
            params: HashMap::new(),
        };
        let v = validate_pipeline(&def);
        assert!(!v.valid);
        assert!(v.errors.iter().any(|e| e.contains("duplicate")));
    }

    #[test]
    fn validate_empty_operation_error() {
        let def = PipelineDef {
            name: "empty-op".to_owned(),
            description: None,
            version: None,
            steps: vec![PipelineStep {
                id: "s1".to_owned(),
                operation: String::new(),
                input: Value::Null,
                depends_on: vec![],
                condition: None,
                on_error: OnError::Abort,
                timeout: None,
            }],
            params: HashMap::new(),
        };
        let v = validate_pipeline(&def);
        assert!(!v.valid);
        assert!(v.errors.iter().any(|e| e.contains("operation is empty")));
    }

    #[test]
    fn validate_self_dependency_error() {
        let def = PipelineDef {
            name: "self-dep".to_owned(),
            description: None,
            version: None,
            steps: vec![PipelineStep {
                id: "s1".to_owned(),
                operation: "g.o".to_owned(),
                input: Value::Null,
                depends_on: vec!["s1".to_owned()],
                condition: None,
                on_error: OnError::Abort,
                timeout: None,
            }],
            params: HashMap::new(),
        };
        let v = validate_pipeline(&def);
        assert!(!v.valid);
        assert!(v.errors.iter().any(|e| e.contains("depends on itself")));
    }

    // ── Template resolution ──────────────────────────────────────

    #[test]
    fn resolve_param_template() {
        let mut params = HashMap::new();
        params.insert("repo".to_owned(), json!("my-repo"));
        let result = resolve_template("{{params.repo}}", &params, &HashMap::new()).unwrap();
        assert_eq!(result, json!("my-repo"));
    }

    #[test]
    fn resolve_step_output_template() {
        let mut outputs = HashMap::new();
        outputs.insert("s1".to_owned(), json!({"count": 42, "items": [1,2,3]}));
        let result =
            resolve_template("{{steps.s1.output.count}}", &HashMap::new(), &outputs).unwrap();
        assert_eq!(result, json!(42));
    }

    #[test]
    fn resolve_step_output_whole() {
        let mut outputs = HashMap::new();
        outputs.insert("s1".to_owned(), json!({"data": "value"}));
        let result = resolve_template("{{steps.s1.output}}", &HashMap::new(), &outputs).unwrap();
        assert_eq!(result, json!({"data": "value"}));
    }

    #[test]
    fn resolve_nested_step_output() {
        let mut outputs = HashMap::new();
        outputs.insert("s1".to_owned(), json!({"response": {"id": 123}}));
        let result =
            resolve_template("{{steps.s1.output.response.id}}", &HashMap::new(), &outputs).unwrap();
        assert_eq!(result, json!(123));
    }

    #[test]
    fn resolve_missing_param_error() {
        let result = resolve_template("{{params.missing}}", &HashMap::new(), &HashMap::new());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn resolve_missing_step_output_error() {
        let result = resolve_template("{{steps.missing.output}}", &HashMap::new(), &HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn resolve_invalid_reference_error() {
        let result = resolve_template("{{unknown.ref}}", &HashMap::new(), &HashMap::new());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown template reference"));
    }

    #[test]
    fn resolve_no_templates() {
        let result = resolve_template("plain text", &HashMap::new(), &HashMap::new()).unwrap();
        assert_eq!(result, json!("plain text"));
    }

    #[test]
    fn resolve_multiple_params_in_string() {
        let mut params = HashMap::new();
        params.insert("owner".to_owned(), json!("org"));
        params.insert("repo".to_owned(), json!("project"));
        let result =
            resolve_template("{{params.owner}}/{{params.repo}}", &params, &HashMap::new()).unwrap();
        assert_eq!(result, json!("org/project"));
    }

    #[test]
    fn resolve_param_bool() {
        let mut params = HashMap::new();
        params.insert("flag".to_owned(), json!(true));
        let result = resolve_template("{{params.flag}}", &params, &HashMap::new()).unwrap();
        assert_eq!(result, json!(true));
    }

    #[test]
    fn resolve_param_number() {
        let mut params = HashMap::new();
        params.insert("count".to_owned(), json!(99));
        let result = resolve_template("{{params.count}}", &params, &HashMap::new()).unwrap();
        assert_eq!(result, json!(99));
    }

    #[test]
    fn resolve_step_output_missing_field_error() {
        let mut outputs = HashMap::new();
        outputs.insert("s1".to_owned(), json!({"a": 1}));
        let result = resolve_template("{{steps.s1.output.nonexistent}}", &HashMap::new(), &outputs);
        assert!(result.is_err());
    }

    // ── Dependency ordering / execution planning ─────────────────

    #[test]
    fn plan_linear_chain() {
        let def = parse_pipeline_toml(minimal_toml()).unwrap();
        let plan = plan_execution(&def);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0], vec!["s1"]);
        assert_eq!(plan[1], vec!["s2"]);
    }

    #[test]
    fn plan_diamond() {
        let def = parse_pipeline_toml(diamond_toml()).unwrap();
        let plan = plan_execution(&def);
        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0], vec!["root"]);
        assert_eq!(plan[1].len(), 2);
        assert!(plan[1].contains(&"left".to_owned()));
        assert!(plan[1].contains(&"right".to_owned()));
        assert_eq!(plan[2], vec!["join"]);
    }

    #[test]
    fn plan_all_independent() {
        let toml = r#"
name = "independent"

[[steps]]
id = "a"
operation = "g.o"

[[steps]]
id = "b"
operation = "g.o"

[[steps]]
id = "c"
operation = "g.o"
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        let plan = plan_execution(&def);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].len(), 3);
    }

    #[test]
    fn plan_single_step() {
        let toml = r#"
name = "single"

[[steps]]
id = "only"
operation = "g.o"
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        let plan = plan_execution(&def);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0], vec!["only"]);
    }

    #[test]
    fn plan_long_chain_10_steps() {
        let mut steps_toml = String::new();
        for i in 0..10 {
            steps_toml.push_str(&format!(
                "\n[[steps]]\nid = \"s{i}\"\noperation = \"g.o\"\n"
            ));
            if i > 0 {
                steps_toml.push_str(&format!("depends_on = [\"s{}\"]\n", i - 1));
            }
        }
        let toml = format!("name = \"long-chain\"\n{steps_toml}");
        let def = parse_pipeline_toml(&toml).unwrap();
        let plan = plan_execution(&def);
        assert_eq!(plan.len(), 10);
        for (i, wave) in plan.iter().enumerate() {
            assert_eq!(wave.len(), 1);
            assert_eq!(wave[0], format!("s{i}"));
        }
    }

    #[test]
    fn plan_wide_fan_out() {
        let mut steps_toml = String::from("\n[[steps]]\nid = \"root\"\noperation = \"g.o\"\n");
        for i in 0..8 {
            steps_toml.push_str(&format!(
                "\n[[steps]]\nid = \"leaf{i}\"\noperation = \"g.o\"\ndepends_on = [\"root\"]\n"
            ));
        }
        let toml = format!("name = \"fan-out\"\n{steps_toml}");
        let def = parse_pipeline_toml(&toml).unwrap();
        let plan = plan_execution(&def);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].len(), 1);
        assert_eq!(plan[1].len(), 8);
    }

    #[test]
    fn plan_wide_fan_in() {
        let mut steps_toml = String::new();
        let mut deps = Vec::new();
        for i in 0..6 {
            steps_toml.push_str(&format!(
                "\n[[steps]]\nid = \"r{i}\"\noperation = \"g.o\"\n"
            ));
            deps.push(format!("\"r{i}\""));
        }
        steps_toml.push_str(&format!(
            "\n[[steps]]\nid = \"sink\"\noperation = \"g.o\"\ndepends_on = [{}]\n",
            deps.join(", ")
        ));
        let toml = format!("name = \"fan-in\"\n{steps_toml}");
        let def = parse_pipeline_toml(&toml).unwrap();
        let plan = plan_execution(&def);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].len(), 6);
        assert_eq!(plan[1], vec!["sink"]);
    }

    // ── Cycle detection ──────────────────────────────────────────

    #[test]
    fn cycle_three_nodes() {
        let toml = r#"
name = "cycle3"

[[steps]]
id = "a"
operation = "g.o"
depends_on = ["c"]

[[steps]]
id = "b"
operation = "g.o"
depends_on = ["a"]

[[steps]]
id = "c"
operation = "g.o"
depends_on = ["b"]
"#;
        let err = parse_pipeline_toml(toml).unwrap_err();
        match err {
            PipelineError::CycleDetected { step_ids } => assert_eq!(step_ids.len(), 3),
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    #[test]
    fn cycle_with_free_node() {
        let toml = r#"
name = "partial-cycle"

[[steps]]
id = "free"
operation = "g.o"

[[steps]]
id = "a"
operation = "g.o"
depends_on = ["b"]

[[steps]]
id = "b"
operation = "g.o"
depends_on = ["a"]
"#;
        let err = parse_pipeline_toml(toml).unwrap_err();
        match err {
            PipelineError::CycleDetected { step_ids } => {
                assert_eq!(step_ids.len(), 2);
                assert!(!step_ids.contains(&"free".to_owned()));
            }
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    // ── Conditional steps ────────────────────────────────────────

    #[test]
    fn step_with_condition_parsed() {
        let toml = r#"
name = "conditional"

[[steps]]
id = "check"
operation = "g.status"

[[steps]]
id = "act"
operation = "g.deploy"
depends_on = ["check"]
condition = "{{steps.check.output.ready}} == true"
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        assert!(def.steps[1].condition.is_some());
    }

    #[test]
    fn step_without_condition_is_none() {
        let toml = r#"
name = "no-cond"

[[steps]]
id = "s1"
operation = "g.o"
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        assert!(def.steps[0].condition.is_none());
    }

    // ── Error handling modes ─────────────────────────────────────

    #[test]
    fn on_error_default() {
        assert_eq!(OnError::default(), OnError::Abort);
    }

    #[test]
    fn on_error_roundtrip() {
        for mode in [OnError::Abort, OnError::Skip, OnError::Retry] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: OnError = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn on_error_serde_values() {
        assert_eq!(serde_json::to_string(&OnError::Abort).unwrap(), "\"abort\"");
        assert_eq!(serde_json::to_string(&OnError::Skip).unwrap(), "\"skip\"");
        assert_eq!(serde_json::to_string(&OnError::Retry).unwrap(), "\"retry\"");
    }

    // ── ParamType ────────────────────────────────────────────────

    #[test]
    fn param_type_roundtrip() {
        for pt in [ParamType::String, ParamType::Number, ParamType::Bool] {
            let json = serde_json::to_string(&pt).unwrap();
            let back: ParamType = serde_json::from_str(&json).unwrap();
            assert_eq!(pt, back);
        }
    }

    #[test]
    fn param_type_serde_values() {
        assert_eq!(
            serde_json::to_string(&ParamType::String).unwrap(),
            "\"string\""
        );
        assert_eq!(
            serde_json::to_string(&ParamType::Number).unwrap(),
            "\"number\""
        );
        assert_eq!(serde_json::to_string(&ParamType::Bool).unwrap(), "\"bool\"");
    }

    // ── TOON formatting ─────────────────────────────────────────

    #[test]
    fn toon_plan_contains_name() {
        let def = parse_pipeline_toml(minimal_toml()).unwrap();
        let plan = plan_execution(&def);
        let output = format_pipeline_plan_toon(&def, &plan);
        assert!(output.contains("test-pipeline"));
    }

    #[test]
    fn toon_plan_contains_wave_info() {
        let def = parse_pipeline_toml(minimal_toml()).unwrap();
        let plan = plan_execution(&def);
        let output = format_pipeline_plan_toon(&def, &plan);
        assert!(output.contains("Wave 0"));
        assert!(output.contains("Wave 1"));
        assert!(output.contains("s1"));
        assert!(output.contains("s2"));
    }

    #[test]
    fn toon_plan_contains_step_count() {
        let def = parse_pipeline_toml(minimal_toml()).unwrap();
        let plan = plan_execution(&def);
        let output = format_pipeline_plan_toon(&def, &plan);
        assert!(output.contains("Steps: 2"));
    }

    #[test]
    fn toon_plan_with_description() {
        let def = parse_pipeline_toml(diamond_toml()).unwrap();
        let plan = plan_execution(&def);
        let output = format_pipeline_plan_toon(&def, &plan);
        assert!(output.contains("Diamond dependency pattern"));
    }

    #[test]
    fn toon_plan_with_version() {
        let def = parse_pipeline_toml(diamond_toml()).unwrap();
        let plan = plan_execution(&def);
        let output = format_pipeline_plan_toon(&def, &plan);
        assert!(output.contains("Version: 1.0.0"));
    }

    #[test]
    fn toon_plan_with_params() {
        let toml = r#"
name = "with-params"

[params.x]
type = "string"
required = true

[[steps]]
id = "s1"
operation = "g.o"
input = { val = "{{params.x}}" }
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        let plan = plan_execution(&def);
        let output = format_pipeline_plan_toon(&def, &plan);
        assert!(output.contains("Parameters:"));
        assert!(output.contains("x:"));
    }

    #[test]
    fn toon_result_all_pass() {
        let result = PipelineResult {
            name: "test".to_owned(),
            all_passed: true,
            step_results: vec![
                StepResult {
                    step_id: "s1".to_owned(),
                    success: true,
                    output: Some(json!({})),
                    duration: Duration::from_millis(100),
                    skipped: false,
                    error: None,
                },
                StepResult {
                    step_id: "s2".to_owned(),
                    success: true,
                    output: Some(json!({})),
                    duration: Duration::from_millis(200),
                    skipped: false,
                    error: None,
                },
            ],
            duration: Duration::from_millis(300),
            params_used: HashMap::new(),
        };
        let output = format_pipeline_result_toon(&result);
        assert!(output.contains("[PASS]"));
        assert!(output.contains("2/2 passed"));
        assert!(output.contains("s1"));
        assert!(output.contains("s2"));
    }

    #[test]
    fn toon_result_with_failure() {
        let result = PipelineResult {
            name: "fail-test".to_owned(),
            all_passed: false,
            step_results: vec![
                StepResult {
                    step_id: "s1".to_owned(),
                    success: true,
                    output: Some(json!({})),
                    duration: Duration::from_millis(50),
                    skipped: false,
                    error: None,
                },
                StepResult {
                    step_id: "s2".to_owned(),
                    success: false,
                    output: None,
                    duration: Duration::from_millis(10),
                    skipped: false,
                    error: Some("connection refused".to_owned()),
                },
            ],
            duration: Duration::from_millis(60),
            params_used: HashMap::new(),
        };
        let output = format_pipeline_result_toon(&result);
        assert!(output.contains("[FAIL]"));
        assert!(output.contains("1/2 passed"));
        assert!(output.contains("1 failed"));
        assert!(output.contains("connection refused"));
    }

    #[test]
    fn toon_result_with_skipped() {
        let result = PipelineResult {
            name: "skip-test".to_owned(),
            all_passed: false,
            step_results: vec![
                StepResult {
                    step_id: "s1".to_owned(),
                    success: true,
                    output: Some(json!({})),
                    duration: Duration::from_millis(50),
                    skipped: false,
                    error: None,
                },
                StepResult {
                    step_id: "s2".to_owned(),
                    success: false,
                    output: None,
                    duration: Duration::ZERO,
                    skipped: true,
                    error: None,
                },
            ],
            duration: Duration::from_millis(50),
            params_used: HashMap::new(),
        };
        let output = format_pipeline_result_toon(&result);
        assert!(output.contains("1 skipped"));
        assert!(output.contains("SKIP"));
    }

    // ── PipelineError Display ────────────────────────────────────

    #[test]
    fn error_display_toml_parse() {
        let err = PipelineError::TomlParse("bad syntax".to_owned());
        assert!(err.to_string().contains("TOML parse error"));
        assert!(err.to_string().contains("bad syntax"));
    }

    #[test]
    fn error_display_missing_field() {
        let err = PipelineError::MissingField("name".to_owned());
        assert!(err.to_string().contains("missing required field"));
    }

    #[test]
    fn error_display_cycle() {
        let err = PipelineError::CycleDetected {
            step_ids: vec!["a".to_owned(), "b".to_owned()],
        };
        assert!(err.to_string().contains("cycle"));
        assert!(err.to_string().contains("a, b"));
    }

    #[test]
    fn error_display_duplicate() {
        let err = PipelineError::DuplicateStepId("s1".to_owned());
        assert!(err.to_string().contains("duplicate"));
        assert!(err.to_string().contains("s1"));
    }

    #[test]
    fn error_display_empty_pipeline() {
        let err = PipelineError::EmptyPipeline;
        assert!(err.to_string().contains("no steps"));
    }

    #[test]
    fn error_display_unknown_dep() {
        let err = PipelineError::UnknownDependency {
            step_id: "child".to_owned(),
            dependency: "parent".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("child"));
        assert!(msg.contains("parent"));
    }

    #[test]
    fn error_display_invalid_template() {
        let err = PipelineError::InvalidTemplate("bad expr".to_owned());
        assert!(err.to_string().contains("invalid template"));
    }

    #[test]
    fn error_display_invalid_param_type() {
        let err = PipelineError::InvalidParamType("integer".to_owned());
        assert!(err.to_string().contains("invalid parameter type"));
    }

    // ── PipelineError Clone/Eq ───────────────────────────────────

    #[test]
    fn error_clone_all_variants() {
        let variants: Vec<PipelineError> = vec![
            PipelineError::TomlParse("x".to_owned()),
            PipelineError::MissingField("y".to_owned()),
            PipelineError::InvalidStepRef {
                step_id: "a".to_owned(),
                field: "b".to_owned(),
            },
            PipelineError::CycleDetected {
                step_ids: vec!["c".to_owned()],
            },
            PipelineError::UnknownDependency {
                step_id: "d".to_owned(),
                dependency: "e".to_owned(),
            },
            PipelineError::DuplicateStepId("f".to_owned()),
            PipelineError::InvalidTemplate("g".to_owned()),
            PipelineError::InvalidParamType("h".to_owned()),
            PipelineError::EmptyPipeline,
        ];
        for err in &variants {
            let cloned = err.clone();
            assert_eq!(err, &cloned);
        }
    }

    // ── Template extraction ──────────────────────────────────────

    #[test]
    fn extract_no_templates() {
        let refs = extract_template_refs("no templates here");
        assert!(refs.is_empty());
    }

    #[test]
    fn extract_single_template() {
        let refs = extract_template_refs("{{params.x}}");
        assert_eq!(refs, vec!["params.x"]);
    }

    #[test]
    fn extract_multiple_templates() {
        let refs = extract_template_refs("{{params.a}}/{{steps.s1.output.b}}");
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0], "params.a");
        assert_eq!(refs[1], "steps.s1.output.b");
    }

    #[test]
    fn extract_template_with_spaces() {
        let refs = extract_template_refs("{{ params.x }}");
        assert_eq!(refs, vec!["params.x"]);
    }

    #[test]
    fn extract_unclosed_template() {
        let refs = extract_template_refs("{{params.x");
        assert!(refs.is_empty());
    }

    // ── StepResult / PipelineResult serde ────────────────────────

    #[test]
    fn step_result_roundtrip() {
        let sr = StepResult {
            step_id: "s1".to_owned(),
            success: true,
            output: Some(json!({"data": 42})),
            duration: Duration::from_secs(1),
            skipped: false,
            error: None,
        };
        let json = serde_json::to_string(&sr).unwrap();
        let back: StepResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.step_id, "s1");
        assert!(back.success);
    }

    #[test]
    fn step_result_error_roundtrip() {
        let sr = StepResult {
            step_id: "s2".to_owned(),
            success: false,
            output: None,
            duration: Duration::from_millis(500),
            skipped: false,
            error: Some("timeout".to_owned()),
        };
        let json = serde_json::to_string(&sr).unwrap();
        let back: StepResult = serde_json::from_str(&json).unwrap();
        assert!(!back.success);
        assert_eq!(back.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn step_result_skipped() {
        let sr = StepResult {
            step_id: "s3".to_owned(),
            success: false,
            output: None,
            duration: Duration::ZERO,
            skipped: true,
            error: None,
        };
        assert!(sr.skipped);
        assert!(!sr.success);
    }

    #[test]
    fn pipeline_result_roundtrip() {
        let pr = PipelineResult {
            name: "test".to_owned(),
            all_passed: true,
            step_results: vec![StepResult {
                step_id: "s1".to_owned(),
                success: true,
                output: Some(json!({})),
                duration: Duration::from_secs(2),
                skipped: false,
                error: None,
            }],
            duration: Duration::from_secs(2),
            params_used: {
                let mut m = HashMap::new();
                m.insert("key".to_owned(), json!("val"));
                m
            },
        };
        let json = serde_json::to_string(&pr).unwrap();
        let back: PipelineResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test");
        assert!(back.all_passed);
        assert_eq!(back.step_results.len(), 1);
    }

    // ── PipelineDef Clone/Debug ──────────────────────────────────

    #[test]
    fn pipeline_def_clone() {
        let def = parse_pipeline_toml(minimal_toml()).unwrap();
        let cloned = def.clone();
        assert_eq!(cloned.name, def.name);
        assert_eq!(cloned.steps.len(), def.steps.len());
    }

    #[test]
    fn pipeline_def_debug() {
        let def = parse_pipeline_toml(minimal_toml()).unwrap();
        let debug = format!("{def:?}");
        assert!(debug.contains("PipelineDef"));
        assert!(debug.contains("test-pipeline"));
    }

    // ── PipelineStep Clone/Debug ─────────────────────────────────

    #[test]
    fn pipeline_step_clone() {
        let step = PipelineStep {
            id: "s1".to_owned(),
            operation: "g.o".to_owned(),
            input: json!({"key": "val"}),
            depends_on: vec!["dep".to_owned()],
            condition: Some("{{params.x}} > 0".to_owned()),
            on_error: OnError::Skip,
            timeout: Some(60),
        };
        let cloned = step.clone();
        assert_eq!(cloned.id, step.id);
        assert_eq!(cloned.on_error, OnError::Skip);
        assert_eq!(cloned.timeout, Some(60));
    }

    #[test]
    fn pipeline_step_debug() {
        let step = PipelineStep {
            id: "dbg".to_owned(),
            operation: "g.o".to_owned(),
            input: Value::Null,
            depends_on: vec![],
            condition: None,
            on_error: OnError::Abort,
            timeout: None,
        };
        let debug = format!("{step:?}");
        assert!(debug.contains("PipelineStep"));
    }

    // ── ParamDef serde ───────────────────────────────────────────

    #[test]
    fn param_def_roundtrip() {
        let pd = ParamDef {
            param_type: ParamType::String,
            required: true,
            default_value: None,
            description: Some("A parameter".to_owned()),
        };
        let json = serde_json::to_string(&pd).unwrap();
        let back: ParamDef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.param_type, ParamType::String);
        assert!(back.required);
    }

    #[test]
    fn param_def_with_default() {
        let pd = ParamDef {
            param_type: ParamType::Number,
            required: false,
            default_value: Some(json!(42)),
            description: None,
        };
        let json = serde_json::to_string(&pd).unwrap();
        assert!(json.contains("42"));
    }

    // ── PipelineValidation ───────────────────────────────────────

    #[test]
    fn validation_valid_has_no_errors() {
        let def = parse_pipeline_toml(diamond_toml()).unwrap();
        let v = validate_pipeline(&def);
        assert!(v.valid);
        assert!(v.errors.is_empty());
    }

    #[test]
    fn validation_unknown_dep_error_in_validate() {
        let def = PipelineDef {
            name: "bad".to_owned(),
            description: None,
            version: None,
            steps: vec![PipelineStep {
                id: "s1".to_owned(),
                operation: "g.o".to_owned(),
                input: Value::Null,
                depends_on: vec!["nonexistent".to_owned()],
                condition: None,
                on_error: OnError::Abort,
                timeout: None,
            }],
            params: HashMap::new(),
        };
        let v = validate_pipeline(&def);
        assert!(!v.valid);
        assert!(v.errors.iter().any(|e| e.contains("nonexistent")));
    }

    // ── Integration: parse -> validate -> plan ───────────────────

    #[test]
    fn full_pipeline_workflow() {
        let toml = r#"
name = "deploy-pipeline"
description = "Build, test, and deploy"
version = "2.1.0"

[params.env]
type = "string"
required = true
description = "Target environment"

[params.dry_run]
type = "bool"
required = false
default_value = false

[[steps]]
id = "build"
operation = "ci.build"
input = { project = "{{params.env}}" }

[[steps]]
id = "test"
operation = "ci.test"
depends_on = ["build"]

[[steps]]
id = "deploy"
operation = "infra.deploy"
depends_on = ["test"]
on_error = "retry"
timeout = 300
condition = "{{params.dry_run}} == false"

[[steps]]
id = "notify"
operation = "slack.send"
depends_on = ["deploy"]
on_error = "skip"
"#;
        let def = parse_pipeline_toml(toml).unwrap();
        assert_eq!(def.name, "deploy-pipeline");
        assert_eq!(def.params.len(), 2);
        assert_eq!(def.steps.len(), 4);

        let v = validate_pipeline(&def);
        assert!(v.valid);
        // dry_run has both required=false and default_value → no warning for that
        // env is required no default → fine

        let plan = plan_execution(&def);
        assert_eq!(plan.len(), 4); // linear chain
        assert_eq!(plan[0], vec!["build"]);
        assert_eq!(plan[1], vec!["test"]);
        assert_eq!(plan[2], vec!["deploy"]);
        assert_eq!(plan[3], vec!["notify"]);

        let output = format_pipeline_plan_toon(&def, &plan);
        assert!(output.contains("deploy-pipeline"));
        assert!(output.contains("Build, test, and deploy"));
        assert!(output.contains("Version: 2.1.0"));
        assert!(output.contains("Wave 0"));
        assert!(output.contains("Wave 3"));
    }

    #[test]
    fn full_pipeline_result_workflow() {
        let result = PipelineResult {
            name: "deploy-pipeline".to_owned(),
            all_passed: false,
            step_results: vec![
                StepResult {
                    step_id: "build".to_owned(),
                    success: true,
                    output: Some(json!({"artifact": "build-123"})),
                    duration: Duration::from_secs(45),
                    skipped: false,
                    error: None,
                },
                StepResult {
                    step_id: "test".to_owned(),
                    success: true,
                    output: Some(json!({"passed": 100, "failed": 0})),
                    duration: Duration::from_secs(120),
                    skipped: false,
                    error: None,
                },
                StepResult {
                    step_id: "deploy".to_owned(),
                    success: false,
                    output: None,
                    duration: Duration::from_secs(30),
                    skipped: false,
                    error: Some("connection timeout".to_owned()),
                },
                StepResult {
                    step_id: "notify".to_owned(),
                    success: false,
                    output: None,
                    duration: Duration::ZERO,
                    skipped: true,
                    error: None,
                },
            ],
            duration: Duration::from_secs(195),
            params_used: {
                let mut m = HashMap::new();
                m.insert("env".to_owned(), json!("production"));
                m.insert("dry_run".to_owned(), json!(false));
                m
            },
        };

        let output = format_pipeline_result_toon(&result);
        assert!(output.contains("[FAIL]"));
        assert!(output.contains("2/4 passed"));
        assert!(output.contains("1 failed"));
        assert!(output.contains("1 skipped"));
        assert!(output.contains("connection timeout"));
        assert!(output.contains("build"));
        assert!(output.contains("notify"));
    }
}
