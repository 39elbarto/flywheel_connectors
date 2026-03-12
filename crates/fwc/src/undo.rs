//! Idempotent undo — reverse previous operations using declared inverse mappings.
//!
//! This module looks up an operation's declared inverse and constructs the
//! inverse input from the original input/output using JSON-path-style
//! field mappings.
//!
//! # Design principles
//!
//! - Every undoable operation declares its inverse and a field mapping.
//! - A rich built-in table covers the most common connector pairs.
//! - Custom mappings can be registered at runtime (e.g. loaded from TOML).
//! - Non-reversible operations are flagged with human-readable guidance.
//! - Planning is separate from execution — `plan_undo` never calls connectors.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors that can occur while planning an undo.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UndoError {
    /// The operation has no known inverse.
    NoInverse,
    /// A required field was missing from the original output.
    MissingOutputField(String),
    /// The operation id was not recognized.
    OperationNotFound,
    /// A path expression in the input mapping could not be evaluated.
    InputMappingFailed(String),
}

impl fmt::Display for UndoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInverse => write!(f, "operation has no known inverse"),
            Self::MissingOutputField(field) => {
                write!(f, "missing required output field: {field}")
            }
            Self::OperationNotFound => write!(f, "operation not found"),
            Self::InputMappingFailed(msg) => {
                write!(f, "input mapping failed: {msg}")
            }
        }
    }
}

impl std::error::Error for UndoError {}

// ── Core types ──────────────────────────────────────────────────────────────

/// Describes how to map fields from the original input/output into the inverse
/// operation's input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InverseMapping {
    /// Fully-qualified name of the inverse operation (e.g. `"github.close_issue"`).
    pub inverse_operation: String,
    /// Maps target field names to JSON-path source expressions.
    ///
    /// Paths use a minimal `$.input.<field>` / `$.output.<field>` syntax.
    pub input_mapping: BTreeMap<String, String>,
}

/// A concrete plan to undo a specific operation invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoPlan {
    /// Identifier of the original audit-log entry.
    pub original_entry_id: String,
    /// The operation that was originally performed.
    pub original_operation: String,
    /// The inverse operation that should be called.
    pub inverse_operation: String,
    /// Fully-constructed input for the inverse operation.
    pub inverse_input: serde_json::Value,
    /// Risk level of the inverse operation (e.g. `"low"`, `"medium"`, `"high"`).
    pub risk_level: String,
    /// Whether a human/agent must confirm before execution.
    pub requires_confirmation: bool,
    /// Any caveats or warnings about performing the undo.
    pub warnings: Vec<String>,
}

/// Result of checking whether an operation is reversible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReversibilityCheck {
    /// The operation that was checked.
    pub operation_id: String,
    /// Whether the operation is reversible.
    pub reversible: bool,
    /// The inverse operation, if one exists.
    pub inverse_operation: Option<String>,
    /// Human-readable guidance (especially useful when not reversible).
    pub guidance: String,
}

// ── Registry ────────────────────────────────────────────────────────────────

/// Registry of inverse-operation mappings.
///
/// Ships with a built-in table of common connector pairs and allows
/// additional mappings to be registered at runtime.
#[derive(Clone, Debug)]
pub struct UndoRegistry {
    mappings: BTreeMap<String, InverseMapping>,
    guidance: BTreeMap<String, String>,
}

impl Default for UndoRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UndoRegistry {
    /// Create a new registry pre-loaded with the built-in inverse table.
    #[must_use]
    pub fn new() -> Self {
        let mut reg = Self {
            mappings: BTreeMap::new(),
            guidance: BTreeMap::new(),
        };
        reg.load_builtins();
        reg
    }

    /// Register a custom inverse mapping, returning `&mut Self` for chaining.
    pub fn register(&mut self, operation: &str, mapping: InverseMapping) -> &mut Self {
        self.mappings.insert(operation.to_owned(), mapping);
        self
    }

    /// Look up the inverse mapping for an operation.
    #[must_use]
    pub fn lookup(&self, operation_id: &str) -> Option<&InverseMapping> {
        self.mappings.get(operation_id)
    }

    /// Return the number of registered mappings (built-in + custom).
    #[must_use]
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Return `true` if there are no registered mappings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    // ── Built-in table ──────────────────────────────────────────────────

    #[allow(clippy::too_many_lines)]
    fn load_builtins(&mut self) {
        // Helper to insert a simple mapping with common id-based patterns.
        let mut add = |op: &str, inv: &str, fields: &[(&str, &str)]| {
            let input_mapping = fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            self.mappings.insert(
                op.to_owned(),
                InverseMapping {
                    inverse_operation: inv.to_owned(),
                    input_mapping,
                },
            );
        };

        // GitHub
        add(
            "github.create_issue",
            "github.close_issue",
            &[
                ("owner", "$.input.owner"),
                ("repo", "$.input.repo"),
                ("issue_number", "$.output.issue.number"),
            ],
        );
        add(
            "github.create_pull_request",
            "github.close_pull_request",
            &[
                ("owner", "$.input.owner"),
                ("repo", "$.input.repo"),
                ("pull_number", "$.output.pull_request.number"),
            ],
        );
        add(
            "github.create_repo",
            "github.delete_repo",
            &[("owner", "$.output.owner.login"), ("repo", "$.output.name")],
        );
        add(
            "github.add_label",
            "github.remove_label",
            &[
                ("owner", "$.input.owner"),
                ("repo", "$.input.repo"),
                ("issue_number", "$.input.issue_number"),
                ("label", "$.input.label"),
            ],
        );

        // Slack
        add(
            "slack.send_message",
            "slack.delete_message",
            &[("channel", "$.input.channel"), ("ts", "$.output.ts")],
        );

        // Discord
        add(
            "discord.send_message",
            "discord.delete_message",
            &[
                ("channel_id", "$.input.channel_id"),
                ("message_id", "$.output.id"),
            ],
        );

        // Todoist
        add(
            "todoist.create_task",
            "todoist.close_task",
            &[("task_id", "$.output.id")],
        );

        // Linear
        add(
            "linear.create_issue",
            "linear.close_issue",
            &[("issue_id", "$.output.id")],
        );

        // Notion
        add(
            "notion.create_page",
            "notion.archive_page",
            &[("page_id", "$.output.id")],
        );

        // Jira
        add(
            "jira.create_issue",
            "jira.close_issue",
            &[
                ("issue_key", "$.output.key"),
                ("project", "$.input.project"),
            ],
        );

        // Trello
        add(
            "trello.create_card",
            "trello.archive_card",
            &[("card_id", "$.output.id")],
        );

        // Asana
        add(
            "asana.create_task",
            "asana.close_task",
            &[("task_gid", "$.output.gid")],
        );

        // Kubernetes
        add(
            "kubernetes.create_pod",
            "kubernetes.delete_pod",
            &[("namespace", "$.input.namespace"), ("name", "$.input.name")],
        );

        // Terraform
        add(
            "terraform.apply",
            "terraform.destroy",
            &[
                ("workspace", "$.input.workspace"),
                ("config_dir", "$.input.config_dir"),
            ],
        );

        // S3
        add(
            "s3.upload_object",
            "s3.delete_object",
            &[("bucket", "$.input.bucket"), ("key", "$.input.key")],
        );

        // Stripe
        add(
            "stripe.create_subscription",
            "stripe.cancel_subscription",
            &[("subscription_id", "$.output.id")],
        );

        // Spotify
        add(
            "spotify.follow_playlist",
            "spotify.unfollow_playlist",
            &[("playlist_id", "$.input.playlist_id")],
        );

        // Generic create/delete, enable/disable, add/remove
        add("generic.create", "generic.delete", &[("id", "$.output.id")]);
        add("generic.enable", "generic.disable", &[("id", "$.input.id")]);
        add("generic.add", "generic.remove", &[("id", "$.input.id")]);
        add("generic.start", "generic.stop", &[("id", "$.input.id")]);
        add(
            "generic.subscribe",
            "generic.unsubscribe",
            &[("subscription_id", "$.output.id")],
        );

        // Non-reversible operations — guidance only.
        self.guidance.insert(
            "gmail.send_email".to_owned(),
            "Emails cannot be unsent. Consider sending a follow-up correction.".to_owned(),
        );
        self.guidance.insert(
            "openai.create_completion".to_owned(),
            "Completions are stateless and cannot be undone.".to_owned(),
        );
        self.guidance.insert(
            "stripe.charge".to_owned(),
            "Charges can be refunded via stripe.create_refund, not reversed.".to_owned(),
        );
        self.guidance.insert(
            "twilio.send_sms".to_owned(),
            "SMS messages cannot be recalled once delivered.".to_owned(),
        );
    }

    /// Get non-reversible guidance for an operation.
    #[must_use]
    pub fn guidance(&self, operation_id: &str) -> Option<&str> {
        self.guidance.get(operation_id).map(String::as_str)
    }
}

// ── Path evaluation ─────────────────────────────────────────────────────────

/// Evaluate a path expression against the original input and output values.
///
/// Supported syntax:
/// - `$.input.field` — access `field` on the original input
/// - `$.output.field.nested` — access `field.nested` on the original output
/// - `$.input.array[N]` — access array element at index N
///
/// # Errors
///
/// Returns an error string if the path is malformed or the target field does
/// not exist.
pub fn evaluate_path(
    path: &str,
    input: &serde_json::Value,
    output: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let path = path.trim();

    if !path.starts_with("$.") {
        return Err(format!("path must start with '$.' — got: {path}"));
    }

    let rest = &path[2..];

    let (root_name, remainder) = rest
        .find('.')
        .map_or((rest, ""), |idx| (&rest[..idx], &rest[idx + 1..]));

    let root = match root_name {
        "input" => input,
        "output" => output,
        other => {
            return Err(format!(
                "unknown root '{other}' — expected 'input' or 'output'"
            ));
        }
    };

    if remainder.is_empty() {
        return Ok(root.clone());
    }

    resolve_segments(root, remainder)
}

/// Walk dot-separated segments, handling `field[N]` array indexing.
fn resolve_segments(
    mut current: &serde_json::Value,
    path: &str,
) -> Result<serde_json::Value, String> {
    for segment in path.split('.') {
        // Check for array index syntax: field[N]
        if let Some(bracket_pos) = segment.find('[') {
            let field = &segment[..bracket_pos];
            let idx_str = segment[bracket_pos + 1..]
                .strip_suffix(']')
                .ok_or_else(|| format!("malformed array index in segment: {segment}"))?;
            let idx: usize = idx_str
                .parse()
                .map_err(|_| format!("non-numeric array index: {idx_str}"))?;

            // Navigate to the field first (if non-empty).
            if !field.is_empty() {
                current = current
                    .get(field)
                    .ok_or_else(|| format!("field '{field}' not found"))?;
            }
            current = current
                .get(idx)
                .ok_or_else(|| format!("array index {idx} out of bounds"))?;
        } else {
            current = current
                .get(segment)
                .ok_or_else(|| format!("field '{segment}' not found"))?;
        }
    }
    Ok(current.clone())
}

// ── Plan construction ───────────────────────────────────────────────────────

/// Construct an undo plan from the registry, original operation, and its
/// input/output.
///
/// # Errors
///
/// Returns `UndoError` if the operation has no inverse, or if any required
/// field is missing from the original input/output.
pub fn plan_undo(
    registry: &UndoRegistry,
    operation_id: &str,
    original_input: &serde_json::Value,
    original_output: &serde_json::Value,
) -> Result<UndoPlan, UndoError> {
    let mapping = registry.lookup(operation_id).ok_or(UndoError::NoInverse)?;

    let mut inverse_input = serde_json::Map::new();
    let mut warnings: Vec<String> = Vec::new();

    for (target_field, source_path) in &mapping.input_mapping {
        match evaluate_path(source_path, original_input, original_output) {
            Ok(value) => {
                if value.is_null() {
                    warnings.push(format!(
                        "field '{target_field}' resolved to null from path '{source_path}'"
                    ));
                }
                inverse_input.insert(target_field.clone(), value);
            }
            Err(e) => {
                // Distinguish between output-sourced and input-sourced failures.
                if source_path.starts_with("$.output") {
                    return Err(UndoError::MissingOutputField(format!(
                        "{target_field}: {e}"
                    )));
                }
                return Err(UndoError::InputMappingFailed(format!(
                    "{target_field}: {e}"
                )));
            }
        }
    }

    // Determine risk level based on the inverse operation name.
    let risk_level = classify_risk(&mapping.inverse_operation);
    let requires_confirmation = risk_level == "high";

    Ok(UndoPlan {
        original_entry_id: String::new(), // Filled by caller.
        original_operation: operation_id.to_owned(),
        inverse_operation: mapping.inverse_operation.clone(),
        inverse_input: serde_json::Value::Object(inverse_input),
        risk_level,
        requires_confirmation,
        warnings,
    })
}

/// Classify risk for an inverse operation based on its name.
fn classify_risk(operation: &str) -> String {
    let op_lower = operation.to_lowercase();
    if op_lower.contains("delete") || op_lower.contains("destroy") {
        "high".to_owned()
    } else if op_lower.contains("close")
        || op_lower.contains("archive")
        || op_lower.contains("cancel")
        || op_lower.contains("disable")
        || op_lower.contains("stop")
        || op_lower.contains("remove")
    {
        "medium".to_owned()
    } else {
        "low".to_owned()
    }
}

// ── Reversibility check ─────────────────────────────────────────────────────

/// Check whether an operation is reversible without actually planning an undo.
#[must_use]
pub fn check_reversibility(registry: &UndoRegistry, operation_id: &str) -> ReversibilityCheck {
    registry.lookup(operation_id).map_or_else(
        || {
            let guidance = registry.guidance(operation_id).map_or_else(
                || "No known inverse. Manual intervention may be required.".to_owned(),
                ToOwned::to_owned,
            );
            ReversibilityCheck {
                operation_id: operation_id.to_owned(),
                reversible: false,
                inverse_operation: None,
                guidance,
            }
        },
        |mapping| ReversibilityCheck {
            operation_id: operation_id.to_owned(),
            reversible: true,
            inverse_operation: Some(mapping.inverse_operation.clone()),
            guidance: format!("Can be reversed via '{}'.", mapping.inverse_operation),
        },
    )
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── UndoRegistry: built-in lookups ──────────────────────────────────

    #[test]
    fn registry_has_builtin_github_create_issue() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("github.create_issue").unwrap();
        assert_eq!(m.inverse_operation, "github.close_issue");
    }

    #[test]
    fn registry_has_builtin_github_create_pull_request() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("github.create_pull_request").unwrap();
        assert_eq!(m.inverse_operation, "github.close_pull_request");
    }

    #[test]
    fn registry_has_builtin_github_create_repo() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("github.create_repo").unwrap();
        assert_eq!(m.inverse_operation, "github.delete_repo");
    }

    #[test]
    fn registry_has_builtin_github_add_label() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("github.add_label").unwrap();
        assert_eq!(m.inverse_operation, "github.remove_label");
    }

    #[test]
    fn registry_has_builtin_slack_send_message() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("slack.send_message").unwrap();
        assert_eq!(m.inverse_operation, "slack.delete_message");
    }

    #[test]
    fn registry_has_builtin_discord_send_message() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("discord.send_message").unwrap();
        assert_eq!(m.inverse_operation, "discord.delete_message");
    }

    #[test]
    fn registry_has_builtin_todoist_create_task() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("todoist.create_task").unwrap();
        assert_eq!(m.inverse_operation, "todoist.close_task");
    }

    #[test]
    fn registry_has_builtin_linear_create_issue() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("linear.create_issue").unwrap();
        assert_eq!(m.inverse_operation, "linear.close_issue");
    }

    #[test]
    fn registry_has_builtin_notion_create_page() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("notion.create_page").unwrap();
        assert_eq!(m.inverse_operation, "notion.archive_page");
    }

    #[test]
    fn registry_has_builtin_jira_create_issue() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("jira.create_issue").unwrap();
        assert_eq!(m.inverse_operation, "jira.close_issue");
    }

    #[test]
    fn registry_has_builtin_trello_create_card() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("trello.create_card").unwrap();
        assert_eq!(m.inverse_operation, "trello.archive_card");
    }

    #[test]
    fn registry_has_builtin_asana_create_task() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("asana.create_task").unwrap();
        assert_eq!(m.inverse_operation, "asana.close_task");
    }

    #[test]
    fn registry_has_builtin_kubernetes_create_pod() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("kubernetes.create_pod").unwrap();
        assert_eq!(m.inverse_operation, "kubernetes.delete_pod");
    }

    #[test]
    fn registry_has_builtin_terraform_apply() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("terraform.apply").unwrap();
        assert_eq!(m.inverse_operation, "terraform.destroy");
    }

    #[test]
    fn registry_has_builtin_s3_upload_object() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("s3.upload_object").unwrap();
        assert_eq!(m.inverse_operation, "s3.delete_object");
    }

    #[test]
    fn registry_has_builtin_stripe_create_subscription() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("stripe.create_subscription").unwrap();
        assert_eq!(m.inverse_operation, "stripe.cancel_subscription");
    }

    #[test]
    fn registry_has_builtin_spotify_follow_playlist() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("spotify.follow_playlist").unwrap();
        assert_eq!(m.inverse_operation, "spotify.unfollow_playlist");
    }

    #[test]
    fn registry_has_builtin_generic_pairs() {
        let reg = UndoRegistry::new();
        assert_eq!(
            reg.lookup("generic.create").unwrap().inverse_operation,
            "generic.delete"
        );
        assert_eq!(
            reg.lookup("generic.enable").unwrap().inverse_operation,
            "generic.disable"
        );
        assert_eq!(
            reg.lookup("generic.add").unwrap().inverse_operation,
            "generic.remove"
        );
        assert_eq!(
            reg.lookup("generic.start").unwrap().inverse_operation,
            "generic.stop"
        );
        assert_eq!(
            reg.lookup("generic.subscribe").unwrap().inverse_operation,
            "generic.unsubscribe"
        );
    }

    #[test]
    fn registry_has_at_least_20_builtins() {
        let reg = UndoRegistry::new();
        assert!(
            reg.len() >= 20,
            "expected >= 20 builtins, got {}",
            reg.len()
        );
    }

    #[test]
    fn registry_unknown_operation_returns_none() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("nonexistent.op").is_none());
    }

    #[test]
    fn registry_custom_registration() {
        let mut reg = UndoRegistry::new();
        let before = reg.len();
        reg.register(
            "custom.lock",
            InverseMapping {
                inverse_operation: "custom.unlock".to_owned(),
                input_mapping: BTreeMap::from([(
                    "resource_id".to_owned(),
                    "$.output.id".to_owned(),
                )]),
            },
        );
        assert_eq!(reg.len(), before + 1);
        let m = reg.lookup("custom.lock").unwrap();
        assert_eq!(m.inverse_operation, "custom.unlock");
    }

    #[test]
    fn registry_custom_overwrites_builtin() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "github.create_issue",
            InverseMapping {
                inverse_operation: "github.delete_issue".to_owned(),
                input_mapping: BTreeMap::new(),
            },
        );
        assert_eq!(
            reg.lookup("github.create_issue").unwrap().inverse_operation,
            "github.delete_issue"
        );
    }

    #[test]
    fn registry_is_empty_false_after_new() {
        let reg = UndoRegistry::new();
        assert!(!reg.is_empty());
    }

    #[test]
    fn registry_default_equals_new() {
        let a = UndoRegistry::new();
        let b = UndoRegistry::default();
        assert_eq!(a.len(), b.len());
    }

    // ── Path evaluation ─────────────────────────────────────────────────

    #[test]
    fn path_eval_input_field() {
        let input = json!({"owner": "acme", "repo": "widgets"});
        let output = json!({});
        let val = evaluate_path("$.input.owner", &input, &output).unwrap();
        assert_eq!(val, json!("acme"));
    }

    #[test]
    fn path_eval_output_nested() {
        let input = json!({});
        let output = json!({"issue": {"number": 42}});
        let val = evaluate_path("$.output.issue.number", &input, &output).unwrap();
        assert_eq!(val, json!(42));
    }

    #[test]
    fn path_eval_deeply_nested() {
        let input = json!({});
        let output = json!({"a": {"b": {"c": {"d": "deep"}}}});
        let val = evaluate_path("$.output.a.b.c.d", &input, &output).unwrap();
        assert_eq!(val, json!("deep"));
    }

    #[test]
    fn path_eval_array_index() {
        let input = json!({"tags": ["alpha", "beta", "gamma"]});
        let output = json!({});
        let val = evaluate_path("$.input.tags[1]", &input, &output).unwrap();
        assert_eq!(val, json!("beta"));
    }

    #[test]
    fn path_eval_array_index_zero() {
        let input = json!({"items": [10, 20, 30]});
        let output = json!({});
        let val = evaluate_path("$.input.items[0]", &input, &output).unwrap();
        assert_eq!(val, json!(10));
    }

    #[test]
    fn path_eval_missing_field_error() {
        let input = json!({"owner": "acme"});
        let output = json!({});
        let err = evaluate_path("$.input.repo", &input, &output).unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[test]
    fn path_eval_bad_root_error() {
        let input = json!({});
        let output = json!({});
        let err = evaluate_path("$.context.field", &input, &output).unwrap_err();
        assert!(err.contains("unknown root"), "got: {err}");
    }

    #[test]
    fn path_eval_missing_prefix_error() {
        let input = json!({});
        let output = json!({});
        let err = evaluate_path("input.field", &input, &output).unwrap_err();
        assert!(err.contains("must start with"), "got: {err}");
    }

    #[test]
    fn path_eval_array_out_of_bounds() {
        let input = json!({"items": [1]});
        let output = json!({});
        let err = evaluate_path("$.input.items[5]", &input, &output).unwrap_err();
        assert!(err.contains("out of bounds"), "got: {err}");
    }

    #[test]
    fn path_eval_root_only_returns_whole_object() {
        let input = json!({"x": 1});
        let output = json!({});
        let val = evaluate_path("$.input", &input, &output).unwrap();
        assert_eq!(val, json!({"x": 1}));
    }

    #[test]
    fn path_eval_null_value() {
        let input = json!({"field": null});
        let output = json!({});
        let val = evaluate_path("$.input.field", &input, &output).unwrap();
        assert!(val.is_null());
    }

    #[test]
    fn path_eval_boolean_value() {
        let input = json!({});
        let output = json!({"active": true});
        let val = evaluate_path("$.output.active", &input, &output).unwrap();
        assert_eq!(val, json!(true));
    }

    #[test]
    fn path_eval_whitespace_trimmed() {
        let input = json!({"x": 99});
        let output = json!({});
        let val = evaluate_path("  $.input.x  ", &input, &output).unwrap();
        assert_eq!(val, json!(99));
    }

    #[test]
    fn path_eval_malformed_array_bracket() {
        let input = json!({"arr": [1, 2]});
        let output = json!({});
        let err = evaluate_path("$.input.arr[0", &input, &output).unwrap_err();
        assert!(err.contains("malformed"), "got: {err}");
    }

    #[test]
    fn path_eval_non_numeric_array_index() {
        let input = json!({"arr": [1, 2]});
        let output = json!({});
        let err = evaluate_path("$.input.arr[abc]", &input, &output).unwrap_err();
        assert!(err.contains("non-numeric"), "got: {err}");
    }

    // ── Plan construction ───────────────────────────────────────────────

    #[test]
    fn plan_simple_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"owner": "acme", "repo": "widgets"});
        let output = json!({"issue": {"number": 7}});
        let plan = plan_undo(&reg, "github.create_issue", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "github.close_issue");
        assert_eq!(plan.inverse_input["owner"], json!("acme"));
        assert_eq!(plan.inverse_input["repo"], json!("widgets"));
        assert_eq!(plan.inverse_input["issue_number"], json!(7));
    }

    #[test]
    fn plan_slack_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"channel": "C123"});
        let output = json!({"ts": "1234567890.123456"});
        let plan = plan_undo(&reg, "slack.send_message", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "slack.delete_message");
        assert_eq!(plan.inverse_input["channel"], json!("C123"));
        assert_eq!(plan.inverse_input["ts"], json!("1234567890.123456"));
    }

    #[test]
    fn plan_missing_output_field_error() {
        let reg = UndoRegistry::new();
        let input = json!({"owner": "acme", "repo": "w"});
        let output = json!({}); // Missing issue.number
        let err = plan_undo(&reg, "github.create_issue", &input, &output).unwrap_err();
        assert_eq!(
            std::mem::discriminant(&err),
            std::mem::discriminant(&UndoError::MissingOutputField(String::new()))
        );
    }

    #[test]
    fn plan_missing_input_field_error() {
        let reg = UndoRegistry::new();
        let input = json!({}); // Missing owner
        let output = json!({"issue": {"number": 1}});
        let err = plan_undo(&reg, "github.create_issue", &input, &output).unwrap_err();
        assert_eq!(
            std::mem::discriminant(&err),
            std::mem::discriminant(&UndoError::InputMappingFailed(String::new()))
        );
    }

    #[test]
    fn plan_no_inverse_error() {
        let reg = UndoRegistry::new();
        let err = plan_undo(&reg, "unknown.op", &json!({}), &json!({})).unwrap_err();
        assert_eq!(err, UndoError::NoInverse);
    }

    #[test]
    fn plan_risk_level_high_for_delete() {
        let reg = UndoRegistry::new();
        let input = json!({"owner": "a", "repo": "b"});
        let output = json!({"owner": {"login": "a"}, "name": "b"});
        let plan = plan_undo(&reg, "github.create_repo", &input, &output).unwrap();
        assert_eq!(plan.risk_level, "high");
        assert!(plan.requires_confirmation);
    }

    #[test]
    fn plan_risk_level_medium_for_close() {
        let reg = UndoRegistry::new();
        let input = json!({"owner": "a", "repo": "b"});
        let output = json!({"issue": {"number": 1}});
        let plan = plan_undo(&reg, "github.create_issue", &input, &output).unwrap();
        assert_eq!(plan.risk_level, "medium");
        assert!(!plan.requires_confirmation);
    }

    #[test]
    fn plan_risk_level_low_for_generic() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "custom.foo",
            InverseMapping {
                inverse_operation: "custom.bar".to_owned(),
                input_mapping: BTreeMap::new(),
            },
        );
        let plan = plan_undo(&reg, "custom.foo", &json!({}), &json!({})).unwrap();
        assert_eq!(plan.risk_level, "low");
        assert!(!plan.requires_confirmation);
    }

    #[test]
    fn plan_null_value_generates_warning() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "test.op",
            InverseMapping {
                inverse_operation: "test.inv".to_owned(),
                input_mapping: BTreeMap::from([("f".to_owned(), "$.input.f".to_owned())]),
            },
        );
        let plan = plan_undo(&reg, "test.op", &json!({"f": null}), &json!({})).unwrap();
        assert!(!plan.warnings.is_empty());
        assert!(plan.warnings[0].contains("null"));
    }

    #[test]
    fn plan_empty_mapping_produces_empty_input() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "test.noop",
            InverseMapping {
                inverse_operation: "test.noop_inv".to_owned(),
                input_mapping: BTreeMap::new(),
            },
        );
        let plan = plan_undo(&reg, "test.noop", &json!({}), &json!({})).unwrap();
        assert_eq!(plan.inverse_input, json!({}));
    }

    #[test]
    fn plan_complex_mapping() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "ci.deploy",
            InverseMapping {
                inverse_operation: "ci.rollback".to_owned(),
                input_mapping: BTreeMap::from([
                    ("environment".to_owned(), "$.input.environment".to_owned()),
                    (
                        "previous_version".to_owned(),
                        "$.output.deployment.previous_version".to_owned(),
                    ),
                    ("service".to_owned(), "$.input.service".to_owned()),
                ]),
            },
        );
        let input = json!({
            "environment": "production",
            "service": "api-gateway",
            "version": "v2.1.0"
        });
        let output = json!({
            "deployment": {
                "id": "dep-123",
                "previous_version": "v2.0.0",
                "status": "complete"
            }
        });
        let plan = plan_undo(&reg, "ci.deploy", &input, &output).unwrap();
        assert_eq!(plan.inverse_input["environment"], json!("production"));
        assert_eq!(plan.inverse_input["previous_version"], json!("v2.0.0"));
        assert_eq!(plan.inverse_input["service"], json!("api-gateway"));
    }

    // ── Reversibility check ─────────────────────────────────────────────

    #[test]
    fn reversibility_check_reversible() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "github.create_issue");
        assert!(check.reversible);
        assert_eq!(
            check.inverse_operation,
            Some("github.close_issue".to_owned())
        );
        assert!(check.guidance.contains("close_issue"));
    }

    #[test]
    fn reversibility_check_non_reversible_with_guidance() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "gmail.send_email");
        assert!(!check.reversible);
        assert!(check.inverse_operation.is_none());
        assert!(check.guidance.contains("cannot be unsent"));
    }

    #[test]
    fn reversibility_check_openai_completion() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "openai.create_completion");
        assert!(!check.reversible);
        assert!(check.guidance.contains("stateless"));
    }

    #[test]
    fn reversibility_check_unknown_operation() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "mystery.op");
        assert!(!check.reversible);
        assert!(check.inverse_operation.is_none());
        assert!(check.guidance.contains("Manual intervention"));
    }

    // ── Serialization round-trips ───────────────────────────────────────

    #[test]
    fn undo_plan_serde_roundtrip() {
        let plan = UndoPlan {
            original_entry_id: "entry-42".to_owned(),
            original_operation: "github.create_issue".to_owned(),
            inverse_operation: "github.close_issue".to_owned(),
            inverse_input: json!({"owner": "acme", "issue_number": 7}),
            risk_level: "medium".to_owned(),
            requires_confirmation: false,
            warnings: vec!["field was null".to_owned()],
        };
        let json_str = serde_json::to_string(&plan).unwrap();
        let restored: UndoPlan = serde_json::from_str(&json_str).unwrap();
        assert_eq!(plan, restored);
    }

    #[test]
    fn inverse_mapping_serde_roundtrip() {
        let mapping = InverseMapping {
            inverse_operation: "github.close_issue".to_owned(),
            input_mapping: BTreeMap::from([
                ("owner".to_owned(), "$.input.owner".to_owned()),
                (
                    "issue_number".to_owned(),
                    "$.output.issue.number".to_owned(),
                ),
            ]),
        };
        let json_str = serde_json::to_string(&mapping).unwrap();
        let restored: InverseMapping = serde_json::from_str(&json_str).unwrap();
        assert_eq!(mapping, restored);
    }

    #[test]
    fn undo_error_serde_roundtrip() {
        let errors = vec![
            UndoError::NoInverse,
            UndoError::MissingOutputField("ts".to_owned()),
            UndoError::OperationNotFound,
            UndoError::InputMappingFailed("bad path".to_owned()),
        ];
        for err in &errors {
            let json_str = serde_json::to_string(err).unwrap();
            let restored: UndoError = serde_json::from_str(&json_str).unwrap();
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn reversibility_check_serde_roundtrip() {
        let check = ReversibilityCheck {
            operation_id: "slack.send_message".to_owned(),
            reversible: true,
            inverse_operation: Some("slack.delete_message".to_owned()),
            guidance: "Can be reversed.".to_owned(),
        };
        let json_str = serde_json::to_string(&check).unwrap();
        let restored: ReversibilityCheck = serde_json::from_str(&json_str).unwrap();
        assert_eq!(check, restored);
    }

    // ── UndoError Display ───────────────────────────────────────────────

    #[test]
    fn undo_error_display_no_inverse() {
        let err = UndoError::NoInverse;
        assert_eq!(err.to_string(), "operation has no known inverse");
    }

    #[test]
    fn undo_error_display_missing_output_field() {
        let err = UndoError::MissingOutputField("ts".to_owned());
        assert!(err.to_string().contains("ts"));
    }

    #[test]
    fn undo_error_display_operation_not_found() {
        let err = UndoError::OperationNotFound;
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn undo_error_display_input_mapping_failed() {
        let err = UndoError::InputMappingFailed("bad path".to_owned());
        assert!(err.to_string().contains("bad path"));
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn plan_with_array_path_in_output() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "test.batch",
            InverseMapping {
                inverse_operation: "test.unbatch".to_owned(),
                input_mapping: BTreeMap::from([(
                    "first_id".to_owned(),
                    "$.output.created[0]".to_owned(),
                )]),
            },
        );
        let output = json!({"created": ["id-a", "id-b"]});
        let plan = plan_undo(&reg, "test.batch", &json!({}), &output).unwrap();
        assert_eq!(plan.inverse_input["first_id"], json!("id-a"));
    }

    #[test]
    fn plan_preserves_original_operation() {
        let reg = UndoRegistry::new();
        let input = json!({"channel": "C1"});
        let output = json!({"ts": "123"});
        let plan = plan_undo(&reg, "slack.send_message", &input, &output).unwrap();
        assert_eq!(plan.original_operation, "slack.send_message");
    }

    #[test]
    fn classify_risk_destroy_is_high() {
        assert_eq!(classify_risk("terraform.destroy"), "high");
    }

    #[test]
    fn classify_risk_archive_is_medium() {
        assert_eq!(classify_risk("notion.archive_page"), "medium");
    }

    #[test]
    fn classify_risk_unfollow_is_low() {
        assert_eq!(classify_risk("spotify.unfollow_playlist"), "low");
    }

    #[test]
    fn guidance_gmail() {
        let reg = UndoRegistry::new();
        let g = reg.guidance("gmail.send_email").unwrap();
        assert!(g.contains("cannot be unsent"));
    }

    #[test]
    fn guidance_openai() {
        let reg = UndoRegistry::new();
        let g = reg.guidance("openai.create_completion").unwrap();
        assert!(g.contains("stateless"));
    }

    #[test]
    fn guidance_unknown_is_none() {
        let reg = UndoRegistry::new();
        assert!(reg.guidance("unknown.op").is_none());
    }

    #[test]
    fn guidance_twilio() {
        let reg = UndoRegistry::new();
        let g = reg.guidance("twilio.send_sms").unwrap();
        assert!(g.contains("recalled"));
    }

    #[test]
    fn guidance_stripe_charge() {
        let reg = UndoRegistry::new();
        let g = reg.guidance("stripe.charge").unwrap();
        assert!(g.contains("refund"));
    }

    // ── Clone impls ──────────────────────────────────────────────────────

    #[test]
    fn undo_error_clone() {
        let err = UndoError::MissingOutputField("ts".to_owned());
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn undo_error_clone_no_inverse() {
        let err = UndoError::NoInverse;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn undo_error_clone_operation_not_found() {
        let err = UndoError::OperationNotFound;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn undo_error_clone_input_mapping_failed() {
        let err = UndoError::InputMappingFailed("path broken".to_owned());
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn inverse_mapping_clone() {
        let mapping = InverseMapping {
            inverse_operation: "github.close_issue".to_owned(),
            input_mapping: BTreeMap::from([("owner".to_owned(), "$.input.owner".to_owned())]),
        };
        let cloned = mapping.clone();
        assert_eq!(mapping, cloned);
    }

    #[test]
    fn undo_plan_clone() {
        let plan = UndoPlan {
            original_entry_id: "e1".to_owned(),
            original_operation: "op.a".to_owned(),
            inverse_operation: "op.b".to_owned(),
            inverse_input: json!({"x": 1}),
            risk_level: "low".to_owned(),
            requires_confirmation: false,
            warnings: vec!["w1".to_owned()],
        };
        let cloned = plan.clone();
        assert_eq!(plan, cloned);
    }

    #[test]
    fn reversibility_check_clone() {
        let check = ReversibilityCheck {
            operation_id: "test.op".to_owned(),
            reversible: true,
            inverse_operation: Some("test.inv".to_owned()),
            guidance: "ok".to_owned(),
        };
        let cloned = check.clone();
        assert_eq!(check, cloned);
    }

    #[test]
    fn undo_registry_clone() {
        let reg = UndoRegistry::new();
        let cloned = reg.clone();
        assert_eq!(reg.len(), cloned.len());
        // Verify a lookup works on clone
        assert!(cloned.lookup("github.create_issue").is_some());
    }

    // ── Debug impls ──────────────────────────────────────────────────────

    #[test]
    fn undo_error_debug() {
        let err = UndoError::NoInverse;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NoInverse"));
    }

    #[test]
    fn inverse_mapping_debug() {
        let mapping = InverseMapping {
            inverse_operation: "test.inv".to_owned(),
            input_mapping: BTreeMap::new(),
        };
        let dbg = format!("{mapping:?}");
        assert!(dbg.contains("test.inv"));
    }

    #[test]
    fn undo_plan_debug() {
        let plan = UndoPlan {
            original_entry_id: "e1".to_owned(),
            original_operation: "op.a".to_owned(),
            inverse_operation: "op.b".to_owned(),
            inverse_input: json!({}),
            risk_level: "low".to_owned(),
            requires_confirmation: false,
            warnings: vec![],
        };
        let dbg = format!("{plan:?}");
        assert!(dbg.contains("op.a"));
    }

    #[test]
    fn reversibility_check_debug() {
        let check = ReversibilityCheck {
            operation_id: "x".to_owned(),
            reversible: false,
            inverse_operation: None,
            guidance: "none".to_owned(),
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("reversible"));
    }

    #[test]
    fn undo_registry_debug() {
        let reg = UndoRegistry::new();
        let dbg = format!("{reg:?}");
        assert!(dbg.contains("UndoRegistry"));
    }

    // ── UndoError as std::error::Error ───────────────────────────────────

    #[test]
    fn undo_error_is_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(UndoError::NoInverse);
        assert!(err.to_string().contains("no known inverse"));
    }

    #[test]
    fn undo_error_source_is_none() {
        use std::error::Error;
        let err = UndoError::NoInverse;
        assert!(err.source().is_none());
    }

    // ── More path evaluation edge cases ──────────────────────────────────

    #[test]
    fn path_eval_output_root_returns_whole_output() {
        let input = json!({});
        let output = json!({"result": "ok"});
        let val = evaluate_path("$.output", &input, &output).unwrap();
        assert_eq!(val, json!({"result": "ok"}));
    }

    #[test]
    fn path_eval_numeric_value() {
        let input = json!({"count": 42});
        let output = json!({});
        let val = evaluate_path("$.input.count", &input, &output).unwrap();
        assert_eq!(val, json!(42));
    }

    #[test]
    fn path_eval_float_value() {
        let input = json!({"price": 9.99});
        let output = json!({});
        let val = evaluate_path("$.input.price", &input, &output).unwrap();
        assert_eq!(val, json!(9.99));
    }

    #[test]
    fn path_eval_nested_object_returned_as_object() {
        let input = json!({});
        let output = json!({"meta": {"key": "val", "num": 1}});
        let val = evaluate_path("$.output.meta", &input, &output).unwrap();
        assert!(val.is_object());
        assert_eq!(val["key"], json!("val"));
    }

    #[test]
    fn path_eval_array_returned_as_array() {
        let input = json!({"tags": ["a", "b"]});
        let output = json!({});
        let val = evaluate_path("$.input.tags", &input, &output).unwrap();
        assert!(val.is_array());
        assert_eq!(val.as_array().unwrap().len(), 2);
    }

    #[test]
    fn path_eval_nested_array_index() {
        let input = json!({});
        let output = json!({"data": {"items": [100, 200, 300]}});
        let val = evaluate_path("$.output.data.items[2]", &input, &output).unwrap();
        assert_eq!(val, json!(300));
    }

    #[test]
    fn path_eval_empty_string_value() {
        let input = json!({"name": ""});
        let output = json!({});
        let val = evaluate_path("$.input.name", &input, &output).unwrap();
        assert_eq!(val, json!(""));
    }

    #[test]
    fn path_eval_empty_array_at_field() {
        let input = json!({"items": []});
        let output = json!({});
        let val = evaluate_path("$.input.items", &input, &output).unwrap();
        assert_eq!(val, json!([]));
    }

    #[test]
    fn path_eval_empty_array_index_out_of_bounds() {
        let input = json!({"items": []});
        let output = json!({});
        let err = evaluate_path("$.input.items[0]", &input, &output).unwrap_err();
        assert!(err.contains("out of bounds"), "got: {err}");
    }

    #[test]
    fn path_eval_bare_array_index_on_root_array() {
        // When root itself might need indexing — but evaluate_path requires $.input/output first
        let input = json!({"arr": [[1, 2], [3, 4]]});
        let output = json!({});
        let val = evaluate_path("$.input.arr[1]", &input, &output).unwrap();
        assert_eq!(val, json!([3, 4]));
    }

    #[test]
    fn path_eval_nested_object_in_array() {
        let input = json!({});
        let output = json!({"results": [{"id": "a"}, {"id": "b"}]});
        let val = evaluate_path("$.output.results[1]", &input, &output).unwrap();
        assert_eq!(val, json!({"id": "b"}));
    }

    #[test]
    fn path_eval_dollar_only_is_error() {
        let err = evaluate_path("$", &json!({}), &json!({})).unwrap_err();
        assert!(err.contains("must start with"), "got: {err}");
    }

    #[test]
    fn path_eval_dollar_dot_only_unknown_root() {
        // "$." means rest="" → root_name="" which is unknown
        let err = evaluate_path("$.", &json!({}), &json!({})).unwrap_err();
        assert!(err.contains("unknown root"), "got: {err}");
    }

    #[test]
    fn path_eval_triple_nested_field() {
        let input = json!({});
        let output = json!({"level1": {"level2": {"level3": {"level4": 999}}}});
        let val = evaluate_path("$.output.level1.level2.level3.level4", &input, &output).unwrap();
        assert_eq!(val, json!(999));
    }

    #[test]
    fn path_eval_field_not_found_on_non_object() {
        let input = json!({"x": 42});
        let output = json!({});
        let err = evaluate_path("$.input.x.y", &input, &output).unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    // ── More plan_undo scenarios ─────────────────────────────────────────

    #[test]
    fn plan_discord_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"channel_id": "ch-1"});
        let output = json!({"id": "msg-42"});
        let plan = plan_undo(&reg, "discord.send_message", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "discord.delete_message");
        assert_eq!(plan.inverse_input["channel_id"], json!("ch-1"));
        assert_eq!(plan.inverse_input["message_id"], json!("msg-42"));
        assert_eq!(plan.risk_level, "high");
    }

    #[test]
    fn plan_todoist_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "task-99"});
        let plan = plan_undo(&reg, "todoist.create_task", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "todoist.close_task");
        assert_eq!(plan.inverse_input["task_id"], json!("task-99"));
    }

    #[test]
    fn plan_linear_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "LIN-42"});
        let plan = plan_undo(&reg, "linear.create_issue", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "linear.close_issue");
        assert_eq!(plan.inverse_input["issue_id"], json!("LIN-42"));
    }

    #[test]
    fn plan_notion_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "page-abc"});
        let plan = plan_undo(&reg, "notion.create_page", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "notion.archive_page");
        assert_eq!(plan.inverse_input["page_id"], json!("page-abc"));
        assert_eq!(plan.risk_level, "medium");
    }

    #[test]
    fn plan_jira_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"project": "PROJ"});
        let output = json!({"key": "PROJ-123"});
        let plan = plan_undo(&reg, "jira.create_issue", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "jira.close_issue");
        assert_eq!(plan.inverse_input["issue_key"], json!("PROJ-123"));
        assert_eq!(plan.inverse_input["project"], json!("PROJ"));
    }

    #[test]
    fn plan_trello_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "card-7"});
        let plan = plan_undo(&reg, "trello.create_card", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "trello.archive_card");
        assert_eq!(plan.inverse_input["card_id"], json!("card-7"));
    }

    #[test]
    fn plan_asana_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"gid": "12345"});
        let plan = plan_undo(&reg, "asana.create_task", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "asana.close_task");
        assert_eq!(plan.inverse_input["task_gid"], json!("12345"));
    }

    #[test]
    fn plan_kubernetes_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"namespace": "default", "name": "my-pod"});
        let output = json!({});
        let plan = plan_undo(&reg, "kubernetes.create_pod", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "kubernetes.delete_pod");
        assert_eq!(plan.inverse_input["namespace"], json!("default"));
        assert_eq!(plan.inverse_input["name"], json!("my-pod"));
        assert_eq!(plan.risk_level, "high");
        assert!(plan.requires_confirmation);
    }

    #[test]
    fn plan_terraform_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"workspace": "prod", "config_dir": "/infra"});
        let output = json!({});
        let plan = plan_undo(&reg, "terraform.apply", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "terraform.destroy");
        assert_eq!(plan.inverse_input["workspace"], json!("prod"));
        assert_eq!(plan.inverse_input["config_dir"], json!("/infra"));
        assert_eq!(plan.risk_level, "high");
        assert!(plan.requires_confirmation);
    }

    #[test]
    fn plan_s3_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"bucket": "my-bucket", "key": "path/to/file.txt"});
        let output = json!({});
        let plan = plan_undo(&reg, "s3.upload_object", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "s3.delete_object");
        assert_eq!(plan.inverse_input["bucket"], json!("my-bucket"));
        assert_eq!(plan.inverse_input["key"], json!("path/to/file.txt"));
    }

    #[test]
    fn plan_stripe_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "sub_abc123"});
        let plan = plan_undo(&reg, "stripe.create_subscription", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "stripe.cancel_subscription");
        assert_eq!(plan.inverse_input["subscription_id"], json!("sub_abc123"));
        assert_eq!(plan.risk_level, "medium");
    }

    #[test]
    fn plan_spotify_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"playlist_id": "pl-42"});
        let output = json!({});
        let plan = plan_undo(&reg, "spotify.follow_playlist", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "spotify.unfollow_playlist");
        assert_eq!(plan.inverse_input["playlist_id"], json!("pl-42"));
    }

    #[test]
    fn plan_generic_create_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "gen-1"});
        let plan = plan_undo(&reg, "generic.create", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "generic.delete");
        assert_eq!(plan.inverse_input["id"], json!("gen-1"));
        assert_eq!(plan.risk_level, "high");
    }

    #[test]
    fn plan_generic_enable_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"id": "feat-1"});
        let output = json!({});
        let plan = plan_undo(&reg, "generic.enable", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "generic.disable");
        assert_eq!(plan.inverse_input["id"], json!("feat-1"));
        assert_eq!(plan.risk_level, "medium");
    }

    #[test]
    fn plan_generic_add_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"id": "item-1"});
        let output = json!({});
        let plan = plan_undo(&reg, "generic.add", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "generic.remove");
        assert_eq!(plan.inverse_input["id"], json!("item-1"));
        assert_eq!(plan.risk_level, "medium");
    }

    #[test]
    fn plan_generic_start_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"id": "proc-1"});
        let output = json!({});
        let plan = plan_undo(&reg, "generic.start", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "generic.stop");
        assert_eq!(plan.inverse_input["id"], json!("proc-1"));
        assert_eq!(plan.risk_level, "medium");
    }

    #[test]
    fn plan_generic_subscribe_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "sub-1"});
        let plan = plan_undo(&reg, "generic.subscribe", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "generic.unsubscribe");
        assert_eq!(plan.inverse_input["subscription_id"], json!("sub-1"));
    }

    #[test]
    fn plan_github_add_label_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"owner": "acme", "repo": "w", "issue_number": 5, "label": "bug"});
        let output = json!({});
        let plan = plan_undo(&reg, "github.add_label", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "github.remove_label");
        assert_eq!(plan.inverse_input["label"], json!("bug"));
        assert_eq!(plan.inverse_input["issue_number"], json!(5));
        assert_eq!(plan.risk_level, "medium");
    }

    #[test]
    fn plan_github_pr_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"owner": "acme", "repo": "widgets"});
        let output = json!({"pull_request": {"number": 101}});
        let plan = plan_undo(&reg, "github.create_pull_request", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "github.close_pull_request");
        assert_eq!(plan.inverse_input["pull_number"], json!(101));
    }

    #[test]
    fn plan_github_create_repo_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"owner": {"login": "acme"}, "name": "new-repo"});
        let plan = plan_undo(&reg, "github.create_repo", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "github.delete_repo");
        assert_eq!(plan.inverse_input["owner"], json!("acme"));
        assert_eq!(plan.inverse_input["repo"], json!("new-repo"));
    }

    // ── Multiple warnings ────────────────────────────────────────────────

    #[test]
    fn plan_multiple_null_fields_generate_multiple_warnings() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "test.multi_null",
            InverseMapping {
                inverse_operation: "test.inv".to_owned(),
                input_mapping: BTreeMap::from([
                    ("a".to_owned(), "$.input.a".to_owned()),
                    ("b".to_owned(), "$.input.b".to_owned()),
                    ("c".to_owned(), "$.input.c".to_owned()),
                ]),
            },
        );
        let plan = plan_undo(
            &reg,
            "test.multi_null",
            &json!({"a": null, "b": null, "c": "ok"}),
            &json!({}),
        )
        .unwrap();
        assert_eq!(plan.warnings.len(), 2);
    }

    #[test]
    fn plan_no_warnings_when_all_fields_present() {
        let reg = UndoRegistry::new();
        let input = json!({"channel": "C1"});
        let output = json!({"ts": "123"});
        let plan = plan_undo(&reg, "slack.send_message", &input, &output).unwrap();
        assert!(plan.warnings.is_empty());
    }

    // ── Registry chaining ────────────────────────────────────────────────

    #[test]
    fn registry_register_chaining() {
        let mut reg = UndoRegistry::new();
        let before = reg.len();
        reg.register(
            "chain.a",
            InverseMapping {
                inverse_operation: "chain.a_inv".to_owned(),
                input_mapping: BTreeMap::new(),
            },
        )
        .register(
            "chain.b",
            InverseMapping {
                inverse_operation: "chain.b_inv".to_owned(),
                input_mapping: BTreeMap::new(),
            },
        );
        assert_eq!(reg.len(), before + 2);
        assert!(reg.lookup("chain.a").is_some());
        assert!(reg.lookup("chain.b").is_some());
    }

    // ── classify_risk edge cases ─────────────────────────────────────────

    #[test]
    fn classify_risk_delete_uppercase_is_high() {
        assert_eq!(classify_risk("s3.DELETE_object"), "high");
    }

    #[test]
    fn classify_risk_close_is_medium() {
        assert_eq!(classify_risk("github.close_issue"), "medium");
    }

    #[test]
    fn classify_risk_cancel_is_medium() {
        assert_eq!(classify_risk("stripe.cancel_subscription"), "medium");
    }

    #[test]
    fn classify_risk_disable_is_medium() {
        assert_eq!(classify_risk("generic.disable"), "medium");
    }

    #[test]
    fn classify_risk_stop_is_medium() {
        assert_eq!(classify_risk("generic.stop"), "medium");
    }

    #[test]
    fn classify_risk_remove_is_medium() {
        assert_eq!(classify_risk("github.remove_label"), "medium");
    }

    #[test]
    fn classify_risk_unknown_verb_is_low() {
        assert_eq!(classify_risk("custom.frobnicate"), "low");
    }

    #[test]
    fn classify_risk_empty_string_is_low() {
        assert_eq!(classify_risk(""), "low");
    }

    #[test]
    fn classify_risk_mixed_case_destroy() {
        assert_eq!(classify_risk("infra.DeStRoY_all"), "high");
    }

    // ── Reversibility check for more builtins ────────────────────────────

    #[test]
    fn reversibility_slack_send_message() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "slack.send_message");
        assert!(check.reversible);
        assert_eq!(check.inverse_operation.as_deref(), Some("slack.delete_message"));
    }

    #[test]
    fn reversibility_kubernetes_create_pod() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "kubernetes.create_pod");
        assert!(check.reversible);
        assert_eq!(check.inverse_operation.as_deref(), Some("kubernetes.delete_pod"));
    }

    #[test]
    fn reversibility_stripe_charge_not_reversible() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "stripe.charge");
        assert!(!check.reversible);
        assert!(check.guidance.contains("refund"));
    }

    #[test]
    fn reversibility_twilio_send_sms_not_reversible() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "twilio.send_sms");
        assert!(!check.reversible);
        assert!(check.guidance.contains("recalled"));
    }

    #[test]
    fn reversibility_terraform_apply() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "terraform.apply");
        assert!(check.reversible);
        assert_eq!(check.inverse_operation.as_deref(), Some("terraform.destroy"));
    }

    #[test]
    fn reversibility_check_operation_id_preserved() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "github.create_issue");
        assert_eq!(check.operation_id, "github.create_issue");
    }

    #[test]
    fn reversibility_check_guidance_format_for_reversible() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "s3.upload_object");
        assert!(check.guidance.starts_with("Can be reversed via"));
    }

    // ── Serde edge cases ─────────────────────────────────────────────────

    #[test]
    fn undo_plan_serde_with_empty_warnings() {
        let plan = UndoPlan {
            original_entry_id: String::new(),
            original_operation: "op".to_owned(),
            inverse_operation: "inv".to_owned(),
            inverse_input: json!({}),
            risk_level: "low".to_owned(),
            requires_confirmation: false,
            warnings: vec![],
        };
        let json_str = serde_json::to_string(&plan).unwrap();
        let restored: UndoPlan = serde_json::from_str(&json_str).unwrap();
        assert_eq!(plan, restored);
        assert!(restored.warnings.is_empty());
    }

    #[test]
    fn undo_plan_serde_with_complex_inverse_input() {
        let plan = UndoPlan {
            original_entry_id: "e".to_owned(),
            original_operation: "op".to_owned(),
            inverse_operation: "inv".to_owned(),
            inverse_input: json!({"nested": {"deep": [1, 2, 3]}, "flag": true}),
            risk_level: "high".to_owned(),
            requires_confirmation: true,
            warnings: vec!["w1".to_owned(), "w2".to_owned()],
        };
        let json_str = serde_json::to_string(&plan).unwrap();
        let restored: UndoPlan = serde_json::from_str(&json_str).unwrap();
        assert_eq!(plan, restored);
    }

    #[test]
    fn inverse_mapping_serde_empty_input_mapping() {
        let mapping = InverseMapping {
            inverse_operation: "test.inv".to_owned(),
            input_mapping: BTreeMap::new(),
        };
        let json_str = serde_json::to_string(&mapping).unwrap();
        let restored: InverseMapping = serde_json::from_str(&json_str).unwrap();
        assert_eq!(mapping, restored);
    }

    #[test]
    fn reversibility_check_serde_not_reversible() {
        let check = ReversibilityCheck {
            operation_id: "gmail.send_email".to_owned(),
            reversible: false,
            inverse_operation: None,
            guidance: "Cannot be unsent.".to_owned(),
        };
        let json_str = serde_json::to_string(&check).unwrap();
        let restored: ReversibilityCheck = serde_json::from_str(&json_str).unwrap();
        assert_eq!(check, restored);
    }

    // ── Equality / inequality ────────────────────────────────────────────

    #[test]
    fn undo_error_ne_different_variants() {
        assert_ne!(UndoError::NoInverse, UndoError::OperationNotFound);
    }

    #[test]
    fn undo_error_ne_different_fields() {
        assert_ne!(
            UndoError::MissingOutputField("a".to_owned()),
            UndoError::MissingOutputField("b".to_owned()),
        );
    }

    #[test]
    fn undo_plan_ne_different_risk() {
        let plan_a = UndoPlan {
            original_entry_id: String::new(),
            original_operation: "op".to_owned(),
            inverse_operation: "inv".to_owned(),
            inverse_input: json!({}),
            risk_level: "low".to_owned(),
            requires_confirmation: false,
            warnings: vec![],
        };
        let mut plan_b = plan_a.clone();
        plan_b.risk_level = "high".to_owned();
        assert_ne!(plan_a, plan_b);
    }

    // ── Builtin mapping field counts ─────────────────────────────────────

    #[test]
    fn github_create_issue_mapping_has_three_fields() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("github.create_issue").unwrap();
        assert_eq!(m.input_mapping.len(), 3);
    }

    #[test]
    fn slack_mapping_has_two_fields() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("slack.send_message").unwrap();
        assert_eq!(m.input_mapping.len(), 2);
    }

    #[test]
    fn todoist_mapping_has_one_field() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("todoist.create_task").unwrap();
        assert_eq!(m.input_mapping.len(), 1);
    }

    #[test]
    fn github_add_label_mapping_has_four_fields() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("github.add_label").unwrap();
        assert_eq!(m.input_mapping.len(), 4);
    }

    #[test]
    fn terraform_mapping_has_two_fields() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("terraform.apply").unwrap();
        assert_eq!(m.input_mapping.len(), 2);
    }

    // ── plan_undo original_entry_id is empty ─────────────────────────────

    #[test]
    fn plan_original_entry_id_is_empty() {
        let reg = UndoRegistry::new();
        let input = json!({"channel": "C1"});
        let output = json!({"ts": "t1"});
        let plan = plan_undo(&reg, "slack.send_message", &input, &output).unwrap();
        assert!(plan.original_entry_id.is_empty());
    }

    // ── path evaluation with special characters ──────────────────────────

    #[test]
    fn path_eval_value_with_special_chars() {
        let input = json!({"msg": "hello world! @#$%"});
        let output = json!({});
        let val = evaluate_path("$.input.msg", &input, &output).unwrap();
        assert_eq!(val, json!("hello world! @#$%"));
    }

    #[test]
    fn path_eval_unicode_value() {
        let input = json!({"name": "caf\u{00e9}"});
        let output = json!({});
        let val = evaluate_path("$.input.name", &input, &output).unwrap();
        assert_eq!(val, json!("caf\u{00e9}"));
    }

    #[test]
    fn path_eval_large_array_index() {
        let mut arr = Vec::new();
        for i in 0..50 {
            arr.push(json!(i));
        }
        let input = json!({"big": arr});
        let output = json!({});
        let val = evaluate_path("$.input.big[49]", &input, &output).unwrap();
        assert_eq!(val, json!(49));
    }
}
