//! Two-operation pipe and named pipeline planning primitives.
//!
//! The pipe module provides a mapping engine that transforms JSON output
//! from one operation into valid input for another, with support for
//! path expressions, literal values, and template strings.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

// ── Map expression types ────────────────────────────────────────────────

/// A single field mapping rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapRule {
    /// Source expression (JSON path like `"issues[0].title"` or literal `"\"#general\""`).
    pub source: String,
    /// Target field name in the destination input.
    pub target: String,
}

/// A complete mapping specification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MappingSpec {
    pub rules: Vec<MapRule>,
}

/// Error from mapping evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct MappingError {
    pub source: String,
    pub target: String,
    pub message: String,
}

impl std::fmt::Display for MappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}: {}", self.source, self.target, self.message)
    }
}

/// Result of applying a mapping specification.
#[derive(Debug)]
pub struct MappingResult {
    /// The produced output object.
    pub output: Value,
    /// Any mapping errors encountered.
    pub errors: Vec<MappingError>,
}

// ── Parsing ─────────────────────────────────────────────────────────────

/// Parse a `--map` expression string into a `MappingSpec`.
///
/// Format: `"source.path -> target, source2 -> target2"`
pub fn parse_map_expression(expr: &str) -> Result<MappingSpec, String> {
    let mut rules = Vec::new();
    for segment in expr.split(',') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let Some((source, target)) = segment.split_once("->") else {
            return Err(format!("invalid mapping rule (missing ->): '{segment}'"));
        };
        let source = source.trim().to_owned();
        let target = target.trim().to_owned();
        if source.is_empty() {
            return Err(format!("empty source in mapping rule: '{segment}'"));
        }
        if target.is_empty() {
            return Err(format!("empty target in mapping rule: '{segment}'"));
        }
        rules.push(MapRule { source, target });
    }
    if rules.is_empty() {
        return Err("no mapping rules found".to_owned());
    }
    Ok(MappingSpec { rules })
}

/// Parse a JSON mapping file into a `MappingSpec`.
///
/// File format: `[{"source": "a.x", "target": "b.x"}, ...]`
pub fn parse_map_file(content: &str) -> Result<MappingSpec, String> {
    let rules: Vec<MapRule> =
        serde_json::from_str(content).map_err(|e| format!("invalid map file JSON: {e}"))?;
    if rules.is_empty() {
        return Err("map file contains no rules".to_owned());
    }
    Ok(MappingSpec { rules })
}

// ── Evaluation ──────────────────────────────────────────────────────────

/// Apply a mapping specification to transform source output into target input.
pub fn apply_mapping(source_output: &Value, spec: &MappingSpec) -> MappingResult {
    let mut output = Map::new();
    let mut errors = Vec::new();

    for rule in &spec.rules {
        match resolve_source(&rule.source, source_output) {
            Some(value) => {
                set_target(&mut output, &rule.target, value);
            }
            None => {
                errors.push(MappingError {
                    source: rule.source.clone(),
                    target: rule.target.clone(),
                    message: format!(
                        "source path '{}' not found in operation output",
                        rule.source
                    ),
                });
            }
        }
    }

    MappingResult {
        output: Value::Object(output),
        errors,
    }
}

/// Resolve a source expression against the source output.
fn resolve_source(source: &str, output: &Value) -> Option<Value> {
    // Check for literal string (quoted).
    if source.starts_with('"') && source.ends_with('"') && source.len() >= 2 {
        let literal = &source[1..source.len() - 1];
        return Some(Value::String(literal.to_owned()));
    }

    // Check for literal number.
    if let Ok(n) = source.parse::<i64>() {
        return Some(Value::Number(n.into()));
    }

    // Check for literal boolean.
    match source {
        "true" => return Some(Value::Bool(true)),
        "false" => return Some(Value::Bool(false)),
        "null" => return Some(Value::Null),
        _ => {}
    }

    // Path resolution.
    resolve_json_path(output, source)
}

/// Resolve a dotted JSON path with array index support.
///
/// Examples: `"title"`, `"user.login"`, `"items[0].name"`, `"labels[0]"`
fn resolve_json_path(value: &Value, path: &str) -> Option<Value> {
    let mut current = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            continue;
        }
        // Handle array index notation.
        if let Some((key, rest)) = segment.split_once('[') {
            // Navigate to the key first.
            if !key.is_empty() {
                current = current.get(key)?;
            }
            // Parse the index.
            let idx_str = rest.strip_suffix(']')?;
            let idx: usize = idx_str.parse().ok()?;
            current = current.as_array()?.get(idx)?;
        } else {
            current = current.get(segment)?;
        }
    }
    Some(current.clone())
}

/// Set a value in the output map, supporting nested targets via dot notation.
fn set_target(output: &mut Map<String, Value>, target: &str, value: Value) {
    let parts: Vec<&str> = target.split('.').collect();
    if parts.len() == 1 {
        output.insert(target.to_owned(), value);
        return;
    }

    // Navigate/create nested objects.
    let mut current = output;
    for part in &parts[..parts.len() - 1] {
        let entry = current
            .entry((*part).to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        current = match entry {
            Value::Object(map) => map,
            _ => return, // Can't nest into non-object.
        };
    }
    if let Some(last) = parts.last() {
        current.insert((*last).to_owned(), value);
    }
}

// ── Pipe plan (for dry-run) ─────────────────────────────────────────────

/// A pipe execution plan for preview/dry-run.
#[derive(Debug, Clone, Serialize)]
pub struct PipePlan {
    /// Source operation ID.
    pub source_operation: String,
    /// Target operation ID.
    pub target_operation: String,
    /// Mapping rules applied.
    pub mapping: MappingSpec,
    /// Whether the target operation is risky and requires approval.
    pub requires_approval: bool,
    /// Estimated output for the target (if dry-run with source output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_input: Option<Value>,
}

// ── Named pipeline definitions ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineMetadata {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStep {
    pub id: String,
    pub operation: String,
    #[serde(default = "default_pipeline_input")]
    pub input: toml::Value,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineParamSpec {
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<toml::Value>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineDefinition {
    pub pipeline: PipelineMetadata,
    #[serde(default)]
    pub steps: Vec<PipelineStep>,
    #[serde(default)]
    pub params: BTreeMap<String, PipelineParamSpec>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineValidation {
    pub valid: bool,
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub execution_order: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineParamBinding {
    pub declared_type: String,
    pub source: String,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlannedPipelineStep {
    pub id: String,
    pub operation: String,
    pub depends_on: Vec<String>,
    pub input: Value,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unresolved_templates: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unresolved_condition_templates: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelinePlan {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub step_count: usize,
    pub execution_order: Vec<String>,
    pub params: BTreeMap<String, PipelineParamBinding>,
    pub steps: Vec<PlannedPipelineStep>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredPipeline {
    pub name: String,
    pub path: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub step_count: usize,
    pub valid: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PipelineRoots {
    pub project: PathBuf,
    pub user: Option<PathBuf>,
}

#[derive(Debug)]
struct RenderedTemplate {
    text: String,
    unresolved: Vec<String>,
}

#[derive(Debug)]
struct RenderedValue {
    value: Value,
    unresolved: Vec<String>,
}

fn default_pipeline_input() -> toml::Value {
    toml::Value::Table(toml::map::Map::new())
}

pub fn parse_pipeline_definition(content: &str) -> Result<PipelineDefinition, String> {
    toml::from_str(content).map_err(|error| format!("invalid pipeline TOML: {error}"))
}

pub fn validate_pipeline_definition(definition: &PipelineDefinition) -> PipelineValidation {
    let mut errors = Vec::new();

    if definition.pipeline.name.trim().is_empty() {
        errors.push("pipeline.name must not be empty".to_owned());
    }

    if definition.steps.is_empty() {
        errors.push("pipeline must declare at least one [[steps]] entry".to_owned());
    }

    let mut seen_step_ids = BTreeSet::new();
    for step in &definition.steps {
        if step.id.trim().is_empty() {
            errors.push("every pipeline step needs a non-empty id".to_owned());
        }
        if step.operation.trim().is_empty() {
            errors.push(format!(
                "step `{}` must declare a non-empty operation",
                step.id
            ));
        }
        if !seen_step_ids.insert(step.id.clone()) {
            errors.push(format!("duplicate pipeline step id `{}`", step.id));
        }
    }

    let known_steps = definition
        .steps
        .iter()
        .map(|step| step.id.as_str())
        .collect::<BTreeSet<_>>();
    for step in &definition.steps {
        for dependency in &step.depends_on {
            if dependency == &step.id {
                errors.push(format!("step `{}` cannot depend on itself", step.id));
            } else if !known_steps.contains(dependency.as_str()) {
                errors.push(format!(
                    "step `{}` depends on unknown step `{dependency}`",
                    step.id
                ));
            }
        }
    }

    for (name, spec) in &definition.params {
        if name.trim().is_empty() {
            errors.push("parameter names must not be empty".to_owned());
        }
        if !is_supported_param_type(&spec.type_name) {
            errors.push(format!(
                "parameter `{name}` uses unsupported type `{}`",
                spec.type_name
            ));
        }
        if let Some(default) = &spec.default {
            match toml_to_json(default) {
                Ok(value) if !value_matches_type(&value, &spec.type_name) => errors.push(format!(
                    "parameter `{name}` has a default value that does not match type `{}`",
                    spec.type_name
                )),
                Err(error) => errors.push(format!(
                    "parameter `{name}` default value could not be serialized: {error}"
                )),
                Ok(_) => {}
            }
        }
    }

    let execution_order = if errors.is_empty() {
        match compute_execution_order(definition) {
            Ok(order) => order,
            Err(error) => {
                errors.push(error);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    PipelineValidation {
        valid: errors.is_empty(),
        errors,
        execution_order,
    }
}

pub fn bind_pipeline_params(
    definition: &PipelineDefinition,
    raw_params: &[String],
) -> Result<BTreeMap<String, PipelineParamBinding>, Vec<String>> {
    let mut errors = Vec::new();
    let mut cli_params = BTreeMap::new();

    for raw in raw_params {
        let Some((key, raw_value)) = raw.split_once('=') else {
            errors.push(format!(
                "invalid `--param` value `{raw}`; expected KEY=VALUE"
            ));
            continue;
        };

        if !definition.params.contains_key(key) {
            errors.push(format!("unknown pipeline parameter `{key}`"));
            continue;
        }

        cli_params.insert(key.to_owned(), parse_cli_param_value(raw_value));
    }

    let mut bindings = BTreeMap::new();
    for (name, spec) in &definition.params {
        let (source, value) = if let Some(value) = cli_params.remove(name) {
            ("cli".to_owned(), value)
        } else if let Some(default) = &spec.default {
            match toml_to_json(default) {
                Ok(value) => ("default".to_owned(), value),
                Err(error) => {
                    errors.push(format!(
                        "parameter `{name}` default value could not be serialized: {error}"
                    ));
                    continue;
                }
            }
        } else if spec.required {
            errors.push(format!("missing required pipeline parameter `{name}`"));
            continue;
        } else {
            continue;
        };

        if !value_matches_type(&value, &spec.type_name) {
            errors.push(format!(
                "parameter `{name}` expected type `{}` but received {}",
                spec.type_name,
                json_type_name(&value)
            ));
            continue;
        }

        bindings.insert(
            name.clone(),
            PipelineParamBinding {
                declared_type: spec.type_name.clone(),
                source,
                value,
            },
        );
    }

    if errors.is_empty() {
        Ok(bindings)
    } else {
        Err(errors)
    }
}

pub fn build_pipeline_plan(
    definition: &PipelineDefinition,
    params: &BTreeMap<String, PipelineParamBinding>,
) -> Result<PipelinePlan, String> {
    let execution_order = compute_execution_order(definition)?;
    let steps_by_id = definition
        .steps
        .iter()
        .map(|step| (step.id.as_str(), step))
        .collect::<BTreeMap<_, _>>();
    let param_values = params
        .iter()
        .map(|(name, binding)| (name.clone(), binding.value.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut steps = Vec::with_capacity(execution_order.len());
    for step_id in &execution_order {
        let step = steps_by_id
            .get(step_id.as_str())
            .ok_or_else(|| format!("pipeline step `{step_id}` disappeared during planning"))?;
        let input = toml_to_json(&step.input)?;
        let rendered_input = render_value_with_params(input, &param_values);
        let (condition, unresolved_condition_templates) =
            step.condition
                .as_deref()
                .map_or((None, Vec::new()), |template| {
                    let rendered = render_template_with_params(template, &param_values);
                    (Some(rendered.text), rendered.unresolved)
                });

        steps.push(PlannedPipelineStep {
            id: step.id.clone(),
            operation: step.operation.clone(),
            depends_on: step.depends_on.clone(),
            input: rendered_input.value,
            unresolved_templates: rendered_input.unresolved,
            condition,
            unresolved_condition_templates,
        });
    }

    Ok(PipelinePlan {
        name: definition.pipeline.name.clone(),
        description: definition.pipeline.description.clone(),
        version: definition.pipeline.version.clone(),
        step_count: definition.steps.len(),
        execution_order,
        params: params.clone(),
        steps,
    })
}

pub fn default_pipeline_roots(cwd: &Path) -> PipelineRoots {
    let project = cwd.join(".fwc").join("pipelines");
    let user = std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .map(|home| home.join(".fwc").join("pipelines"));
    PipelineRoots { project, user }
}

pub fn discover_pipelines(roots: &PipelineRoots) -> Result<Vec<DiscoveredPipeline>, String> {
    let mut directories = vec![("project".to_owned(), roots.project.clone())];
    if let Some(user_root) = &roots.user {
        if user_root != &roots.project {
            directories.push(("user".to_owned(), user_root.clone()));
        }
    }
    discover_pipelines_in_directories(&directories)
}

pub fn resolve_pipeline_reference(
    reference: &str,
    roots: &PipelineRoots,
) -> Result<PathBuf, String> {
    let candidate = PathBuf::from(reference);
    if candidate.is_absolute()
        || reference.contains(std::path::MAIN_SEPARATOR)
        || reference.contains('/')
        || Path::new(reference)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
    {
        if candidate.is_file() {
            return Ok(candidate);
        }
        return Err(format!("pipeline file `{reference}` was not found"));
    }

    let matches = discover_pipelines(roots)?
        .into_iter()
        .filter(|pipeline| {
            if pipeline.name == reference {
                return true;
            }
            Path::new(&pipeline.path)
                .file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|stem| stem == reference)
        })
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [] => Err(format!(
            "no pipeline named `{reference}` was found in the project or user pipeline directories"
        )),
        [pipeline] => Ok(PathBuf::from(&pipeline.path)),
        many => Err(format!(
            "pipeline reference `{reference}` is ambiguous; matches: {}",
            many.iter()
                .map(|pipeline| pipeline.path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn discover_pipelines_in_directories(
    directories: &[(String, PathBuf)],
) -> Result<Vec<DiscoveredPipeline>, String> {
    let mut discovered = Vec::new();

    for (scope, root) in directories {
        if !root.exists() {
            continue;
        }
        let entries = std::fs::read_dir(root).map_err(|error| {
            format!(
                "failed to read pipeline directory `{}`: {error}",
                root.display()
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "failed to read a pipeline entry under `{}`: {error}",
                    root.display()
                )
            })?;
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("toml") {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(error) => {
                    discovered.push(DiscoveredPipeline {
                        name: path
                            .file_stem()
                            .and_then(std::ffi::OsStr::to_str)
                            .unwrap_or("unknown")
                            .to_owned(),
                        path: path.display().to_string(),
                        scope: scope.clone(),
                        description: None,
                        version: None,
                        step_count: 0,
                        valid: false,
                        errors: vec![format!(
                            "failed to read pipeline file `{}`: {error}",
                            path.display()
                        )],
                    });
                    continue;
                }
            };

            match parse_pipeline_definition(&content) {
                Ok(definition) => {
                    let validation = validate_pipeline_definition(&definition);
                    discovered.push(DiscoveredPipeline {
                        name: definition.pipeline.name.clone(),
                        path: path.display().to_string(),
                        scope: scope.clone(),
                        description: definition.pipeline.description.clone(),
                        version: definition.pipeline.version.clone(),
                        step_count: definition.steps.len(),
                        valid: validation.valid,
                        errors: validation.errors,
                    });
                }
                Err(error) => discovered.push(DiscoveredPipeline {
                    name: path
                        .file_stem()
                        .and_then(std::ffi::OsStr::to_str)
                        .unwrap_or("unknown")
                        .to_owned(),
                    path: path.display().to_string(),
                    scope: scope.clone(),
                    description: None,
                    version: None,
                    step_count: 0,
                    valid: false,
                    errors: vec![error],
                }),
            }
        }
    }

    discovered.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.name.cmp(&right.name))
            .then(left.path.cmp(&right.path))
    });

    Ok(discovered)
}

fn compute_execution_order(definition: &PipelineDefinition) -> Result<Vec<String>, String> {
    let steps = definition
        .steps
        .iter()
        .map(|step| (step.id.as_str(), step))
        .collect::<BTreeMap<_, _>>();
    let mut states = BTreeMap::new();
    let mut stack = Vec::new();
    let mut order = Vec::new();

    for step in &definition.steps {
        visit_step(
            step.id.as_str(),
            &steps,
            &mut states,
            &mut stack,
            &mut order,
        )?;
    }

    Ok(order)
}

fn visit_step<'a>(
    step_id: &'a str,
    steps: &BTreeMap<&'a str, &'a PipelineStep>,
    states: &mut BTreeMap<&'a str, u8>,
    stack: &mut Vec<&'a str>,
    order: &mut Vec<String>,
) -> Result<(), String> {
    match states.get(step_id).copied() {
        Some(1) => {
            let cycle_start = stack
                .iter()
                .position(|candidate| *candidate == step_id)
                .unwrap_or(0);
            let mut cycle = stack[cycle_start..]
                .iter()
                .map(|step| (*step).to_owned())
                .collect::<Vec<_>>();
            cycle.push(step_id.to_owned());
            return Err(format!(
                "pipeline step dependency cycle detected: {}",
                cycle.join(" -> ")
            ));
        }
        Some(2) => return Ok(()),
        _ => {}
    }

    let step = steps
        .get(step_id)
        .ok_or_else(|| format!("unknown pipeline step `{step_id}`"))?;
    states.insert(step_id, 1);
    stack.push(step_id);

    for dependency in &step.depends_on {
        visit_step(dependency.as_str(), steps, states, stack, order)?;
    }

    stack.pop();
    states.insert(step_id, 2);
    order.push(step_id.to_owned());
    Ok(())
}

fn render_value_with_params(value: Value, params: &BTreeMap<String, Value>) -> RenderedValue {
    match value {
        Value::String(template) => {
            let rendered = render_template_with_params(&template, params);
            RenderedValue {
                value: Value::String(rendered.text),
                unresolved: rendered.unresolved,
            }
        }
        Value::Array(items) => {
            let mut unresolved = Vec::new();
            let mut rendered_items = Vec::with_capacity(items.len());
            for item in items {
                let rendered = render_value_with_params(item, params);
                unresolved.extend(rendered.unresolved);
                rendered_items.push(rendered.value);
            }
            RenderedValue {
                value: Value::Array(rendered_items),
                unresolved,
            }
        }
        Value::Object(fields) => {
            let mut unresolved = Vec::new();
            let mut rendered_fields = Map::new();
            for (key, field) in fields {
                let rendered = render_value_with_params(field, params);
                unresolved.extend(rendered.unresolved);
                rendered_fields.insert(key, rendered.value);
            }
            RenderedValue {
                value: Value::Object(rendered_fields),
                unresolved,
            }
        }
        primitive => RenderedValue {
            value: primitive,
            unresolved: Vec::new(),
        },
    }
}

fn render_template_with_params(
    template: &str,
    params: &BTreeMap<String, Value>,
) -> RenderedTemplate {
    let mut rendered = String::new();
    let mut unresolved = Vec::new();
    let mut cursor = 0;
    let context = Value::Object(Map::from_iter([(
        "params".to_owned(),
        Value::Object(
            params
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect::<Map<_, _>>(),
        ),
    )]));

    while let Some(relative_start) = template[cursor..].find("{{") {
        let start = cursor + relative_start;
        rendered.push_str(&template[cursor..start]);

        let search_start = start + 2;
        let Some(relative_end) = template[search_start..].find("}}") else {
            rendered.push_str(&template[start..]);
            return RenderedTemplate {
                text: rendered,
                unresolved,
            };
        };
        let end = search_start + relative_end;
        let placeholder = template[search_start..end].trim();

        if placeholder.starts_with("params.")
            && !placeholder.contains('|')
            && !placeholder.contains(' ')
        {
            if let Some(value) = resolve_json_path(&context, placeholder) {
                match value {
                    Value::String(text) => rendered.push_str(&text),
                    other => rendered.push_str(&other.to_string()),
                }
            } else {
                unresolved.push(placeholder.to_owned());
                rendered.push_str(&template[start..end + 2]);
            }
        } else {
            unresolved.push(placeholder.to_owned());
            rendered.push_str(&template[start..end + 2]);
        }

        cursor = end + 2;
    }

    rendered.push_str(&template[cursor..]);
    RenderedTemplate {
        text: rendered,
        unresolved,
    }
}

fn parse_cli_param_value(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_owned()))
}

fn toml_to_json(value: &toml::Value) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| format!("failed to serialize TOML value: {error}"))
}

fn is_supported_param_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "string" | "integer" | "number" | "boolean" | "array" | "object" | "any"
    )
}

fn value_matches_type(value: &Value, type_name: &str) -> bool {
    match type_name {
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "any" => true,
        _ => false,
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.as_i64().is_some() || number.as_u64().is_some() => {
            "integer"
        }
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── parse_map_expression ────────────────────────────────────────

    #[test]
    fn parse_simple_rule() {
        let spec = parse_map_expression("title -> text").unwrap();
        assert_eq!(spec.rules.len(), 1);
        assert_eq!(spec.rules[0].source, "title");
        assert_eq!(spec.rules[0].target, "text");
    }

    #[test]
    fn parse_multiple_rules() {
        let spec = parse_map_expression("title -> text, body -> description").unwrap();
        assert_eq!(spec.rules.len(), 2);
        assert_eq!(spec.rules[0].target, "text");
        assert_eq!(spec.rules[1].target, "description");
    }

    #[test]
    fn parse_with_path_expressions() {
        let spec =
            parse_map_expression("issues[0].title -> text, \"#general\" -> channel").unwrap();
        assert_eq!(spec.rules.len(), 2);
        assert_eq!(spec.rules[0].source, "issues[0].title");
        assert_eq!(spec.rules[1].source, "\"#general\"");
    }

    #[test]
    fn parse_trims_whitespace() {
        let spec = parse_map_expression("  title  ->  text  ").unwrap();
        assert_eq!(spec.rules[0].source, "title");
        assert_eq!(spec.rules[0].target, "text");
    }

    #[test]
    fn parse_skips_empty_segments() {
        let spec = parse_map_expression("title -> text, , body -> desc").unwrap();
        assert_eq!(spec.rules.len(), 2);
    }

    #[test]
    fn parse_error_missing_arrow() {
        let err = parse_map_expression("title text").unwrap_err();
        assert!(err.contains("missing ->"));
    }

    #[test]
    fn parse_error_empty_source() {
        let err = parse_map_expression(" -> text").unwrap_err();
        assert!(err.contains("empty source"));
    }

    #[test]
    fn parse_error_empty_target() {
        let err = parse_map_expression("title -> ").unwrap_err();
        assert!(err.contains("empty target"));
    }

    #[test]
    fn parse_error_empty_expression() {
        let err = parse_map_expression("").unwrap_err();
        assert!(err.contains("no mapping rules"));
    }

    // ── parse_map_file ──────────────────────────────────────────────

    #[test]
    fn parse_file_format() {
        let content = r#"[{"source": "title", "target": "text"}]"#;
        let spec = parse_map_file(content).unwrap();
        assert_eq!(spec.rules.len(), 1);
        assert_eq!(spec.rules[0].source, "title");
    }

    #[test]
    fn parse_file_multiple_rules() {
        let content = r#"[
            {"source": "title", "target": "text"},
            {"source": "body", "target": "description"}
        ]"#;
        let spec = parse_map_file(content).unwrap();
        assert_eq!(spec.rules.len(), 2);
    }

    #[test]
    fn parse_file_invalid_json() {
        let err = parse_map_file("not json").unwrap_err();
        assert!(err.contains("invalid map file"));
    }

    #[test]
    fn parse_file_empty_rules() {
        let err = parse_map_file("[]").unwrap_err();
        assert!(err.contains("no rules"));
    }

    // ── resolve_source ──────────────────────────────────────────────

    #[test]
    fn resolve_literal_string() {
        let val = resolve_source("\"#general\"", &json!({}));
        assert_eq!(val, Some(json!("#general")));
    }

    #[test]
    fn resolve_literal_number() {
        let val = resolve_source("42", &json!({}));
        assert_eq!(val, Some(json!(42)));
    }

    #[test]
    fn resolve_literal_true() {
        let val = resolve_source("true", &json!({}));
        assert_eq!(val, Some(json!(true)));
    }

    #[test]
    fn resolve_literal_false() {
        let val = resolve_source("false", &json!({}));
        assert_eq!(val, Some(json!(false)));
    }

    #[test]
    fn resolve_literal_null() {
        let val = resolve_source("null", &json!({}));
        assert_eq!(val, Some(Value::Null));
    }

    #[test]
    fn resolve_simple_path() {
        let output = json!({"title": "Bug report"});
        let val = resolve_source("title", &output);
        assert_eq!(val, Some(json!("Bug report")));
    }

    #[test]
    fn resolve_nested_path() {
        let output = json!({"user": {"login": "octocat"}});
        let val = resolve_source("user.login", &output);
        assert_eq!(val, Some(json!("octocat")));
    }

    #[test]
    fn resolve_array_index() {
        let output = json!({"items": [{"name": "first"}, {"name": "second"}]});
        let val = resolve_source("items[0].name", &output);
        assert_eq!(val, Some(json!("first")));
    }

    #[test]
    fn resolve_array_second_element() {
        let output = json!({"items": [{"name": "first"}, {"name": "second"}]});
        let val = resolve_source("items[1].name", &output);
        assert_eq!(val, Some(json!("second")));
    }

    #[test]
    fn resolve_missing_path() {
        let output = json!({"title": "Bug"});
        let val = resolve_source("nonexistent", &output);
        assert_eq!(val, None);
    }

    #[test]
    fn resolve_deep_nested_path() {
        let output = json!({"a": {"b": {"c": {"d": "deep"}}}});
        let val = resolve_source("a.b.c.d", &output);
        assert_eq!(val, Some(json!("deep")));
    }

    #[test]
    fn resolve_array_out_of_bounds() {
        let output = json!({"items": [{"name": "only"}]});
        let val = resolve_source("items[5].name", &output);
        assert_eq!(val, None);
    }

    #[test]
    fn resolve_bare_array_index() {
        let output = json!(["a", "b", "c"]);
        let val = resolve_source("[1]", &output);
        assert_eq!(val, Some(json!("b")));
    }

    // ── set_target ──────────────────────────────────────────────────

    #[test]
    fn set_simple_target() {
        let mut output = Map::new();
        set_target(&mut output, "text", json!("hello"));
        assert_eq!(output["text"], json!("hello"));
    }

    #[test]
    fn set_nested_target() {
        let mut output = Map::new();
        set_target(&mut output, "metadata.name", json!("test"));
        assert_eq!(output["metadata"]["name"], json!("test"));
    }

    #[test]
    fn set_deep_nested_target() {
        let mut output = Map::new();
        set_target(&mut output, "a.b.c", json!(42));
        assert_eq!(output["a"]["b"]["c"], json!(42));
    }

    #[test]
    fn set_multiple_nested_targets() {
        let mut output = Map::new();
        set_target(&mut output, "user.name", json!("Alice"));
        set_target(&mut output, "user.email", json!("alice@example.com"));
        assert_eq!(output["user"]["name"], json!("Alice"));
        assert_eq!(output["user"]["email"], json!("alice@example.com"));
    }

    // ── apply_mapping ───────────────────────────────────────────────

    #[test]
    fn apply_simple_mapping() {
        let output = json!({"title": "Bug", "body": "Details"});
        let spec = parse_map_expression("title -> text, body -> description").unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["text"], "Bug");
        assert_eq!(result.output["description"], "Details");
    }

    #[test]
    fn apply_mapping_with_literal() {
        let output = json!({"title": "Bug"});
        let spec = parse_map_expression("title -> text, \"#general\" -> channel").unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["text"], "Bug");
        assert_eq!(result.output["channel"], "#general");
    }

    #[test]
    fn apply_mapping_with_path() {
        let output = json!({"issues": [{"title": "Bug", "number": 42}]});
        let spec =
            parse_map_expression("issues[0].title -> text, issues[0].number -> issue_number")
                .unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["text"], "Bug");
        assert_eq!(result.output["issue_number"], 42);
    }

    #[test]
    fn apply_mapping_missing_source() {
        let output = json!({"title": "Bug"});
        let spec = parse_map_expression("missing -> text").unwrap();
        let result = apply_mapping(&output, &spec);
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].message.contains("not found"));
    }

    #[test]
    fn apply_mapping_partial_success() {
        let output = json!({"title": "Bug"});
        let spec = parse_map_expression("title -> text, missing -> desc").unwrap();
        let result = apply_mapping(&output, &spec);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.output["text"], "Bug");
    }

    #[test]
    fn apply_mapping_nested_target() {
        let output = json!({"name": "test"});
        let spec = parse_map_expression("name -> metadata.name").unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["metadata"]["name"], "test");
    }

    #[test]
    fn apply_mapping_empty_output() {
        let output = json!({});
        let spec = parse_map_expression("title -> text").unwrap();
        let result = apply_mapping(&output, &spec);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn apply_mapping_preserves_types() {
        let output = json!({
            "count": 42,
            "active": true,
            "tags": ["a", "b"],
            "meta": {"key": "val"}
        });
        let spec =
            parse_map_expression("count -> num, active -> flag, tags -> labels, meta -> extra")
                .unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["num"], 42);
        assert_eq!(result.output["flag"], true);
        assert_eq!(result.output["labels"], json!(["a", "b"]));
        assert_eq!(result.output["extra"], json!({"key": "val"}));
    }

    // ── MappingSpec serde ───────────────────────────────────────────

    #[test]
    fn mapping_spec_roundtrip() {
        let spec = parse_map_expression("title -> text, body -> desc").unwrap();
        let json = serde_json::to_string(&spec).unwrap();
        let back: MappingSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rules.len(), 2);
        assert_eq!(back.rules[0].source, "title");
    }

    // ── MappingError display ────────────────────────────────────────

    #[test]
    fn mapping_error_display() {
        let err = MappingError {
            source: "a.b".to_owned(),
            target: "c".to_owned(),
            message: "not found".to_owned(),
        };
        assert_eq!(err.to_string(), "a.b -> c: not found");
    }

    // ── PipePlan serialization ──────────────────────────────────────

    #[test]
    fn pipe_plan_serializes() {
        let plan = PipePlan {
            source_operation: "github.list_issues".to_owned(),
            target_operation: "slack.send_message".to_owned(),
            mapping: parse_map_expression("title -> text").unwrap(),
            requires_approval: false,
            preview_input: Some(json!({"text": "Bug report"})),
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["source_operation"], "github.list_issues");
        assert!(json.get("preview_input").is_some());
    }

    #[test]
    fn pipe_plan_skips_none_preview() {
        let plan = PipePlan {
            source_operation: "a".to_owned(),
            target_operation: "b".to_owned(),
            mapping: MappingSpec::default(),
            requires_approval: true,
            preview_input: None,
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert!(json.get("preview_input").is_none());
        assert_eq!(json["requires_approval"], true);
    }

    // ── resolve_json_path edge cases ────────────────────────────────

    #[test]
    fn resolve_path_top_level_array() {
        let val = json!([1, 2, 3]);
        assert_eq!(resolve_json_path(&val, "[2]"), Some(json!(3)));
    }

    #[test]
    fn resolve_path_nested_array() {
        let val = json!({"data": {"items": [10, 20, 30]}});
        assert_eq!(resolve_json_path(&val, "data.items[1]"), Some(json!(20)));
    }

    #[test]
    fn resolve_path_empty_string() {
        let val = json!({"key": "value"});
        // Empty path returns the value itself.
        assert_eq!(resolve_json_path(&val, ""), Some(json!({"key": "value"})));
    }

    #[test]
    fn resolve_path_number_value() {
        let val = json!({"count": 42});
        assert_eq!(resolve_json_path(&val, "count"), Some(json!(42)));
    }

    #[test]
    fn resolve_path_boolean_value() {
        let val = json!({"active": true});
        assert_eq!(resolve_json_path(&val, "active"), Some(json!(true)));
    }

    #[test]
    fn resolve_path_null_value() {
        let val = json!({"field": null});
        assert_eq!(resolve_json_path(&val, "field"), Some(Value::Null));
    }

    // ── MapRule equality ────────────────────────────────────────────

    #[test]
    fn map_rule_equality() {
        let a = MapRule {
            source: "title".to_owned(),
            target: "text".to_owned(),
        };
        let b = MapRule {
            source: "title".to_owned(),
            target: "text".to_owned(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn map_rule_inequality() {
        let a = MapRule {
            source: "title".to_owned(),
            target: "text".to_owned(),
        };
        let b = MapRule {
            source: "body".to_owned(),
            target: "text".to_owned(),
        };
        assert_ne!(a, b);
    }

    // ── Default mapping spec ────────────────────────────────────────

    #[test]
    fn default_mapping_spec_empty() {
        let spec = MappingSpec::default();
        assert!(spec.rules.is_empty());
    }

    // ── Pipeline definitions ───────────────────────────────────────

    #[test]
    fn parse_pipeline_definition_and_validate_execution_order() {
        let definition = parse_pipeline_definition(
            r##"
[pipeline]
name = "notify-on-new-issues"
description = "Check GitHub and notify Slack"
version = "1.0"

[[steps]]
id = "fetch"
operation = "github.list_issues"
input = { owner = "{{params.owner}}", repo = "{{params.repo}}" }

[[steps]]
id = "notify"
operation = "slack.send_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "New issues: {{steps.fetch.output.issues | length}}" }
condition = "{{steps.fetch.output.issues | length}} > 0"

[params.owner]
type = "string"
required = true

[params.repo]
type = "string"
required = true

[params.channel]
type = "string"
default = "#general"
"##,
        )
        .unwrap();

        let validation = validate_pipeline_definition(&definition);
        assert!(validation.valid);
        assert_eq!(validation.execution_order, vec!["fetch", "notify"]);
    }

    #[test]
    fn pipeline_validation_rejects_cycles() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "cycle"

[[steps]]
id = "a"
operation = "github.list_issues"
depends_on = ["b"]

[[steps]]
id = "b"
operation = "slack.send_message"
depends_on = ["a"]
"#,
        )
        .unwrap();

        let validation = validate_pipeline_definition(&definition);
        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("dependency cycle"))
        );
    }

    #[test]
    fn bind_pipeline_params_uses_defaults_and_cli_values() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "params"

[[steps]]
id = "fetch"
operation = "github.list_issues"

[params.owner]
type = "string"
required = true

[params.count]
type = "integer"
default = 5
"#,
        )
        .unwrap();

        let bindings = bind_pipeline_params(
            &definition,
            &["owner=octocat".to_owned(), "count=10".to_owned()],
        )
        .unwrap();

        assert_eq!(bindings["owner"].source, "cli");
        assert_eq!(bindings["owner"].value, json!("octocat"));
        assert_eq!(bindings["count"].value, json!(10));
    }

    #[test]
    fn build_pipeline_plan_renders_params_and_preserves_dynamic_templates() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "notify-on-new-issues"

[[steps]]
id = "fetch"
operation = "github.list_issues"
input = { owner = "{{params.owner}}", repo = "{{params.repo}}" }

[[steps]]
id = "notify"
operation = "slack.send_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "New issues: {{steps.fetch.output.issues | length}}" }
"#,
        )
        .unwrap();

        let bindings = BTreeMap::from([
            (
                "owner".to_owned(),
                PipelineParamBinding {
                    declared_type: "string".to_owned(),
                    source: "cli".to_owned(),
                    value: json!("octocat"),
                },
            ),
            (
                "repo".to_owned(),
                PipelineParamBinding {
                    declared_type: "string".to_owned(),
                    source: "cli".to_owned(),
                    value: json!("hello-world"),
                },
            ),
            (
                "channel".to_owned(),
                PipelineParamBinding {
                    declared_type: "string".to_owned(),
                    source: "default".to_owned(),
                    value: json!("#general"),
                },
            ),
        ]);

        let plan = build_pipeline_plan(&definition, &bindings).unwrap();
        assert_eq!(plan.execution_order, vec!["fetch", "notify"]);
        assert_eq!(plan.steps[0].input["owner"], "octocat");
        assert_eq!(plan.steps[0].input["repo"], "hello-world");
        assert_eq!(plan.steps[1].input["channel"], "#general");
        assert_eq!(
            plan.steps[1].input["text"],
            "New issues: {{steps.fetch.output.issues | length}}"
        );
        assert_eq!(
            plan.steps[1].unresolved_templates,
            vec!["steps.fetch.output.issues | length"]
        );
    }

    #[test]
    fn discover_pipelines_reports_validity_by_directory() {
        let temp_root = std::env::temp_dir().join(format!(
            "fwc-pipeline-discovery-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let project_root = temp_root.join("project");
        let user_root = temp_root.join("user");
        std::fs::create_dir_all(&project_root).unwrap();
        std::fs::create_dir_all(&user_root).unwrap();

        std::fs::write(
            project_root.join("notify.toml"),
            r#"
[pipeline]
name = "notify"

[[steps]]
id = "fetch"
operation = "github.list_issues"
"#,
        )
        .unwrap();
        std::fs::write(user_root.join("broken.toml"), "not valid toml = {").unwrap();

        let discovered = discover_pipelines_in_directories(&[
            ("project".to_owned(), project_root),
            ("user".to_owned(), user_root),
        ])
        .unwrap();

        assert_eq!(discovered.len(), 2);
        assert!(
            discovered
                .iter()
                .any(|pipeline| pipeline.name == "notify" && pipeline.valid)
        );
        assert!(
            discovered
                .iter()
                .any(|pipeline| pipeline.name == "broken" && !pipeline.valid)
        );

        let _ = std::fs::remove_dir_all(&temp_root);
    }
}
