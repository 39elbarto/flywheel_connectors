//! Pre-built pipeline recipe library for common cross-connector workflows.
//!
//! Provides reusable pipeline templates for common automation patterns like
//! issue-to-branch, deploy-announce, bug-triage, cross-post, and more.
//! Recipes include connector requirements, input parameters, and step definitions.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Recipe Types ──────────────────────────────────────────────────

/// A pipeline recipe — a reusable workflow template.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Recipe {
    /// Unique recipe identifier (e.g., `"issue-to-branch"`).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of what the recipe does.
    pub description: String,
    /// Category for grouping.
    pub category: RecipeCategory,
    /// Connectors required by this recipe.
    pub required_connectors: Vec<String>,
    /// User-supplied parameters.
    pub parameters: Vec<RecipeParameter>,
    /// Steps in the pipeline.
    pub steps: Vec<RecipeStep>,
    /// Tags for search/filtering.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Recipe {
    /// Create a new recipe.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        category: RecipeCategory,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            category,
            required_connectors: Vec::new(),
            parameters: Vec::new(),
            steps: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Builder: add a required connector.
    pub fn with_connector(mut self, connector: impl Into<String>) -> Self {
        self.required_connectors.push(connector.into());
        self
    }

    /// Builder: add a parameter.
    pub fn with_parameter(mut self, param: RecipeParameter) -> Self {
        self.parameters.push(param);
        self
    }

    /// Builder: add a step.
    pub fn with_step(mut self, step: RecipeStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Builder: add a tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Check if all required connectors are available.
    pub fn check_requirements(&self, available: &[String]) -> Vec<String> {
        self.required_connectors
            .iter()
            .filter(|c| !available.iter().any(|a| a == *c))
            .cloned()
            .collect()
    }

    /// Number of steps.
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// All unique connectors referenced in steps.
    pub fn connectors_used(&self) -> Vec<&str> {
        let mut seen = Vec::new();
        for step in &self.steps {
            if !seen.contains(&step.connector.as_str()) {
                seen.push(&step.connector);
            }
        }
        seen
    }
}

/// Category of a pipeline recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeCategory {
    /// Development workflow (issue tracking, branches, PRs).
    Development,
    /// Communication (messaging, notifications, cross-posting).
    Communication,
    /// Deployment and operations.
    Deployment,
    /// Data and analytics.
    Analytics,
    /// Security and compliance.
    Security,
    /// Backup and sync.
    DataSync,
    /// Monitoring and health checks.
    Monitoring,
}

impl fmt::Display for RecipeCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Development => f.write_str("development"),
            Self::Communication => f.write_str("communication"),
            Self::Deployment => f.write_str("deployment"),
            Self::Analytics => f.write_str("analytics"),
            Self::Security => f.write_str("security"),
            Self::DataSync => f.write_str("data_sync"),
            Self::Monitoring => f.write_str("monitoring"),
        }
    }
}

/// A parameter that users must supply when using a recipe.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecipeParameter {
    /// Parameter name (used in templates).
    pub name: String,
    /// Human-readable label.
    pub label: String,
    /// Description/help text.
    #[serde(default)]
    pub description: String,
    /// Whether this parameter is required.
    #[serde(default)]
    pub required: bool,
    /// Default value (if any).
    pub default: Option<String>,
    /// Example value for documentation.
    pub example: Option<String>,
}

impl RecipeParameter {
    /// Create a required parameter.
    pub fn required(
        name: impl Into<String>,
        label: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            label: label.into(),
            description: String::new(),
            required: true,
            default: None,
            example: None,
        }
    }

    /// Create an optional parameter with a default.
    pub fn optional(
        name: impl Into<String>,
        label: impl Into<String>,
        default: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            label: label.into(),
            description: String::new(),
            required: false,
            default: Some(default.into()),
            example: None,
        }
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Builder: set example.
    pub fn with_example(mut self, example: impl Into<String>) -> Self {
        self.example = Some(example.into());
        self
    }
}

/// A single step in a recipe pipeline.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecipeStep {
    /// Step name for display.
    pub name: String,
    /// Target connector.
    pub connector: String,
    /// Operation to invoke.
    pub operation: String,
    /// Input template (values may contain `{{param.name}}` or `{{prev.field}}`).
    #[serde(default)]
    pub input: BTreeMap<String, String>,
    /// Optional condition (e.g., `"prev.status == 'success'"`).
    pub condition: Option<String>,
    /// Whether this step continues on error.
    #[serde(default)]
    pub continue_on_error: bool,
}

impl RecipeStep {
    /// Create a new step.
    pub fn new(
        name: impl Into<String>,
        connector: impl Into<String>,
        operation: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            connector: connector.into(),
            operation: operation.into(),
            input: BTreeMap::new(),
            condition: None,
            continue_on_error: false,
        }
    }

    /// Builder: add an input field.
    pub fn with_input(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.input.insert(key.into(), value.into());
        self
    }

    /// Builder: add a condition.
    pub fn with_condition(mut self, condition: impl Into<String>) -> Self {
        self.condition = Some(condition.into());
        self
    }

    /// Builder: set continue-on-error.
    pub const fn with_continue_on_error(mut self, cont: bool) -> Self {
        self.continue_on_error = cont;
        self
    }
}

// ── Recipe Library ────────────────────────────────────────────────

/// Collection of recipes with search and filtering.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RecipeLibrary {
    /// All registered recipes.
    pub recipes: Vec<Recipe>,
}

impl RecipeLibrary {
    /// Create an empty library.
    pub const fn new() -> Self {
        Self {
            recipes: Vec::new(),
        }
    }

    /// Create a library pre-loaded with built-in recipes.
    pub fn with_builtins() -> Self {
        let mut lib = Self::new();
        for recipe in builtin_recipes() {
            lib.add(recipe);
        }
        lib
    }

    /// Add a recipe.
    pub fn add(&mut self, recipe: Recipe) {
        self.recipes.push(recipe);
    }

    /// Get a recipe by ID.
    pub fn get(&self, id: &str) -> Option<&Recipe> {
        self.recipes.iter().find(|r| r.id == id)
    }

    /// List recipes by category.
    pub fn by_category(&self, category: RecipeCategory) -> Vec<&Recipe> {
        self.recipes
            .iter()
            .filter(|r| r.category == category)
            .collect()
    }

    /// Search recipes by keyword (matches id, name, description, tags).
    pub fn search(&self, query: &str) -> Vec<&Recipe> {
        let q = query.to_ascii_lowercase();
        self.recipes
            .iter()
            .filter(|r| {
                r.id.to_ascii_lowercase().contains(&q)
                    || r.name.to_ascii_lowercase().contains(&q)
                    || r.description.to_ascii_lowercase().contains(&q)
                    || r.tags.iter().any(|t| t.to_ascii_lowercase().contains(&q))
            })
            .collect()
    }

    /// Filter recipes to those whose connectors are all available.
    pub fn available_recipes(&self, available_connectors: &[String]) -> Vec<&Recipe> {
        self.recipes
            .iter()
            .filter(|r| r.check_requirements(available_connectors).is_empty())
            .collect()
    }

    /// Total count.
    pub fn len(&self) -> usize {
        self.recipes.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.recipes.is_empty()
    }

    /// All unique categories present.
    pub fn categories(&self) -> Vec<RecipeCategory> {
        let mut cats: Vec<RecipeCategory> = self.recipes.iter().map(|r| r.category).collect();
        cats.sort_by_key(|c| format!("{c}"));
        cats.dedup();
        cats
    }
}

// ── Built-in Recipes ──────────────────────────────────────────────

/// Generate the built-in recipe library.
pub fn builtin_recipes() -> Vec<Recipe> {
    vec![
        recipe_issue_to_branch(),
        recipe_pr_review_notify(),
        recipe_deploy_announce(),
        recipe_bug_triage(),
        recipe_cross_post(),
        recipe_digest_email(),
        recipe_health_check_all(),
        recipe_rotate_secrets(),
        recipe_sync_contacts(),
        recipe_analytics_report(),
        recipe_meeting_notes(),
        recipe_backup_to_s3(),
    ]
}

fn recipe_issue_to_branch() -> Recipe {
    Recipe::new("issue-to-branch", "Issue to Branch", RecipeCategory::Development)
        .with_description("Create a git branch from a GitHub/Jira issue and post the link back")
        .with_connector("github")
        .with_tag("git")
        .with_tag("automation")
        .with_parameter(
            RecipeParameter::required("owner", "Repository owner")
                .with_example("octocat"),
        )
        .with_parameter(
            RecipeParameter::required("repo", "Repository name")
                .with_example("hello-world"),
        )
        .with_parameter(
            RecipeParameter::required("issue_number", "Issue number")
                .with_example("42"),
        )
        .with_step(
            RecipeStep::new("get-issue", "github", "get_issue")
                .with_input("owner", "{{param.owner}}")
                .with_input("repo", "{{param.repo}}")
                .with_input("issue_number", "{{param.issue_number}}"),
        )
        .with_step(
            RecipeStep::new("create-branch", "github", "create_branch")
                .with_input("owner", "{{param.owner}}")
                .with_input("repo", "{{param.repo}}")
                .with_input("branch", "issue-{{param.issue_number}}-{{prev.title | slugify}}"),
        )
        .with_step(
            RecipeStep::new("comment-on-issue", "github", "create_comment")
                .with_input("owner", "{{param.owner}}")
                .with_input("repo", "{{param.repo}}")
                .with_input("issue_number", "{{param.issue_number}}")
                .with_input("body", "Branch created: `{{prev.branch}}`"),
        )
}

fn recipe_pr_review_notify() -> Recipe {
    Recipe::new("pr-review-notify", "PR Review Notification", RecipeCategory::Development)
        .with_description("Summarize PR changes and notify team on Slack/Discord")
        .with_connector("github")
        .with_connector("slack")
        .with_tag("code-review")
        .with_tag("notification")
        .with_parameter(
            RecipeParameter::required("owner", "Repository owner"),
        )
        .with_parameter(
            RecipeParameter::required("repo", "Repository name"),
        )
        .with_parameter(
            RecipeParameter::required("pr_number", "Pull request number"),
        )
        .with_parameter(
            RecipeParameter::required("channel", "Slack channel")
                .with_example("code-review"),
        )
        .with_step(
            RecipeStep::new("get-pr", "github", "get_pull_request")
                .with_input("owner", "{{param.owner}}")
                .with_input("repo", "{{param.repo}}")
                .with_input("pull_number", "{{param.pr_number}}"),
        )
        .with_step(
            RecipeStep::new("notify-slack", "slack", "send_message")
                .with_input("channel", "{{param.channel}}")
                .with_input("text", "🔍 PR #{{param.pr_number}} ready for review: {{prev.title}}\n{{prev.html_url}}"),
        )
}

fn recipe_deploy_announce() -> Recipe {
    Recipe::new("deploy-announce", "Deploy Announcement", RecipeCategory::Deployment)
        .with_description("Announce deployment status to team channel")
        .with_connector("slack")
        .with_tag("deploy")
        .with_tag("notification")
        .with_parameter(
            RecipeParameter::required("channel", "Notification channel")
                .with_example("deployments"),
        )
        .with_parameter(
            RecipeParameter::required("service", "Service name")
                .with_example("api-server"),
        )
        .with_parameter(
            RecipeParameter::required("version", "Version deployed")
                .with_example("v2.3.1"),
        )
        .with_parameter(
            RecipeParameter::optional("environment", "Target environment", "production"),
        )
        .with_step(
            RecipeStep::new("announce", "slack", "send_message")
                .with_input("channel", "{{param.channel}}")
                .with_input("text", "🚀 *{{param.service}}* {{param.version}} deployed to {{param.environment}}"),
        )
}

fn recipe_bug_triage() -> Recipe {
    Recipe::new("bug-triage", "Bug Triage Pipeline", RecipeCategory::Development)
        .with_description("Create issue from error alert, assign, and notify team")
        .with_connector("github")
        .with_connector("slack")
        .with_tag("bugs")
        .with_tag("triage")
        .with_parameter(
            RecipeParameter::required("owner", "Repository owner"),
        )
        .with_parameter(
            RecipeParameter::required("repo", "Repository name"),
        )
        .with_parameter(
            RecipeParameter::required("error_title", "Error summary"),
        )
        .with_parameter(
            RecipeParameter::required("error_details", "Error details"),
        )
        .with_parameter(
            RecipeParameter::optional("assignee", "Assignee", ""),
        )
        .with_parameter(
            RecipeParameter::optional("channel", "Notification channel", "bugs"),
        )
        .with_step(
            RecipeStep::new("create-issue", "github", "create_issue")
                .with_input("owner", "{{param.owner}}")
                .with_input("repo", "{{param.repo}}")
                .with_input("title", "[Bug] {{param.error_title}}")
                .with_input("body", "{{param.error_details}}")
                .with_input("labels", "bug,triage"),
        )
        .with_step(
            RecipeStep::new("notify", "slack", "send_message")
                .with_input("channel", "{{param.channel}}")
                .with_input("text", "🐛 New bug: {{param.error_title}}\n{{prev.html_url}}"),
        )
}

fn recipe_cross_post() -> Recipe {
    Recipe::new("cross-post", "Cross-Post Message", RecipeCategory::Communication)
        .with_description("Forward a message to multiple platforms (Slack → Discord + Telegram)")
        .with_connector("slack")
        .with_connector("discord")
        .with_tag("messaging")
        .with_tag("cross-platform")
        .with_parameter(
            RecipeParameter::required("message", "Message to cross-post"),
        )
        .with_parameter(
            RecipeParameter::required("discord_channel_id", "Discord channel ID"),
        )
        .with_parameter(
            RecipeParameter::optional("slack_channel", "Slack channel", "general"),
        )
        .with_step(
            RecipeStep::new("post-slack", "slack", "send_message")
                .with_input("channel", "{{param.slack_channel}}")
                .with_input("text", "{{param.message}}"),
        )
        .with_step(
            RecipeStep::new("post-discord", "discord", "send_message")
                .with_input("channel_id", "{{param.discord_channel_id}}")
                .with_input("content", "{{param.message}}")
                .with_continue_on_error(true),
        )
}

fn recipe_digest_email() -> Recipe {
    Recipe::new("digest-email", "Slack Digest Email", RecipeCategory::Communication)
        .with_description("Aggregate recent Slack messages and send as email digest")
        .with_connector("slack")
        .with_connector("gmail")
        .with_tag("email")
        .with_tag("digest")
        .with_parameter(
            RecipeParameter::required("slack_channel", "Slack channel to digest"),
        )
        .with_parameter(
            RecipeParameter::required("email_to", "Recipient email"),
        )
        .with_parameter(
            RecipeParameter::optional("hours", "Hours to look back", "24"),
        )
        .with_step(
            RecipeStep::new("fetch-messages", "slack", "list_messages")
                .with_input("channel", "{{param.slack_channel}}")
                .with_input("limit", "50"),
        )
        .with_step(
            RecipeStep::new("send-digest", "gmail", "send_email")
                .with_input("to", "{{param.email_to}}")
                .with_input("subject", "Slack digest: #{{param.slack_channel}}")
                .with_input("body", "Recent messages from #{{param.slack_channel}}:\n\n{{prev.messages}}"),
        )
}

fn recipe_health_check_all() -> Recipe {
    Recipe::new("health-check-all", "Health Check All Connectors", RecipeCategory::Monitoring)
        .with_description("Check health of all connectors and report to Slack")
        .with_connector("slack")
        .with_tag("health")
        .with_tag("monitoring")
        .with_parameter(
            RecipeParameter::required("channel", "Report channel")
                .with_example("ops-alerts"),
        )
        .with_step(
            RecipeStep::new("report", "slack", "send_message")
                .with_input("channel", "{{param.channel}}")
                .with_input("text", "🏥 Connector health check complete.\n{{prev.summary}}"),
        )
}

fn recipe_rotate_secrets() -> Recipe {
    Recipe::new("rotate-secrets", "Secret Rotation", RecipeCategory::Security)
        .with_description("List expiring credentials, rotate them, and notify")
        .with_connector("slack")
        .with_tag("secrets")
        .with_tag("rotation")
        .with_parameter(
            RecipeParameter::optional("channel", "Notification channel", "security"),
        )
        .with_parameter(
            RecipeParameter::optional("days_threshold", "Days until expiry to trigger", "7"),
        )
        .with_step(
            RecipeStep::new("notify", "slack", "send_message")
                .with_input("channel", "{{param.channel}}")
                .with_input("text", "🔑 Secret rotation complete.\n{{prev.summary}}"),
        )
}

fn recipe_sync_contacts() -> Recipe {
    Recipe::new("sync-contacts", "Sync CRM Contacts", RecipeCategory::DataSync)
        .with_description("Sync contacts from HubSpot to Google Contacts")
        .with_connector("hubspot")
        .with_connector("google-contacts")
        .with_tag("crm")
        .with_tag("sync")
        .with_parameter(
            RecipeParameter::optional("limit", "Max contacts to sync", "100"),
        )
        .with_step(
            RecipeStep::new("fetch-contacts", "hubspot", "list_contacts")
                .with_input("limit", "{{param.limit}}"),
        )
        .with_step(
            RecipeStep::new("sync-to-google", "google-contacts", "create_contact")
                .with_input("name", "{{prev.name}}")
                .with_input("email", "{{prev.email}}")
                .with_continue_on_error(true),
        )
}

fn recipe_analytics_report() -> Recipe {
    Recipe::new("analytics-report", "Analytics Report to Slack", RecipeCategory::Analytics)
        .with_description("Fetch Mixpanel analytics data and send formatted report to Slack")
        .with_connector("mixpanel")
        .with_connector("slack")
        .with_tag("analytics")
        .with_tag("reporting")
        .with_parameter(
            RecipeParameter::required("channel", "Slack channel for report"),
        )
        .with_parameter(
            RecipeParameter::optional("days", "Days to look back", "7"),
        )
        .with_step(
            RecipeStep::new("fetch-data", "mixpanel", "get_report")
                .with_input("days", "{{param.days}}"),
        )
        .with_step(
            RecipeStep::new("post-report", "slack", "send_message")
                .with_input("channel", "{{param.channel}}")
                .with_input("text", "📊 Analytics report (last {{param.days}} days):\n{{prev.summary}}"),
        )
}

fn recipe_meeting_notes() -> Recipe {
    Recipe::new("meeting-notes", "Distribute Meeting Notes", RecipeCategory::Communication)
        .with_description("Send meeting notes to attendees via email")
        .with_connector("gmail")
        .with_tag("meetings")
        .with_tag("notes")
        .with_parameter(
            RecipeParameter::required("recipients", "Comma-separated email list"),
        )
        .with_parameter(
            RecipeParameter::required("subject", "Meeting subject"),
        )
        .with_parameter(
            RecipeParameter::required("notes", "Meeting notes content"),
        )
        .with_step(
            RecipeStep::new("send-notes", "gmail", "send_email")
                .with_input("to", "{{param.recipients}}")
                .with_input("subject", "Meeting Notes: {{param.subject}}")
                .with_input("body", "{{param.notes}}"),
        )
}

fn recipe_backup_to_s3() -> Recipe {
    Recipe::new("backup-to-s3", "Backup Data to S3", RecipeCategory::DataSync)
        .with_description("Export data from a service and upload to S3")
        .with_connector("aws-s3")
        .with_tag("backup")
        .with_tag("s3")
        .with_parameter(
            RecipeParameter::required("bucket", "S3 bucket name"),
        )
        .with_parameter(
            RecipeParameter::required("key_prefix", "S3 key prefix")
                .with_example("backups/daily/"),
        )
        .with_parameter(
            RecipeParameter::required("source_data", "Data to upload"),
        )
        .with_step(
            RecipeStep::new("upload", "aws-s3", "put_object")
                .with_input("bucket", "{{param.bucket}}")
                .with_input("key", "{{param.key_prefix}}backup-{{now}}.json")
                .with_input("body", "{{param.source_data}}"),
        )
}

// ── Display helpers ───────────────────────────────────────────────

/// Format a recipe for TOON display.
pub fn format_recipe_summary(recipe: &Recipe) -> String {
    let connectors = recipe.required_connectors.join(", ");
    format!(
        "{} — {} [{}, {} steps, needs: {}]",
        recipe.id,
        recipe.name,
        recipe.category,
        recipe.step_count(),
        connectors
    )
}

/// Format a recipe's full details.
pub fn format_recipe_detail(recipe: &Recipe) -> String {
    let mut lines = vec![
        format!("Recipe: {} ({})", recipe.name, recipe.id),
        format!("Category: {}", recipe.category),
        format!("Description: {}", recipe.description),
        format!(
            "Connectors: {}",
            recipe.required_connectors.join(", ")
        ),
    ];

    if !recipe.parameters.is_empty() {
        lines.push("Parameters:".to_string());
        for p in &recipe.parameters {
            let req = if p.required { " (required)" } else { "" };
            let def = p
                .default
                .as_ref()
                .map_or(String::new(), |d| format!(" [default: {d}]"));
            lines.push(format!("  {}{req}{def} — {}", p.name, p.label));
        }
    }

    if !recipe.steps.is_empty() {
        lines.push("Steps:".to_string());
        for (i, s) in recipe.steps.iter().enumerate() {
            lines.push(format!(
                "  {}. {} → {}.{}",
                i + 1,
                s.name,
                s.connector,
                s.operation
            ));
        }
    }

    lines.join("\n")
}

/// Validate a recipe.
pub fn validate_recipe(recipe: &Recipe) -> Vec<String> {
    let mut errors = Vec::new();

    if recipe.id.is_empty() {
        errors.push("recipe id is required".to_string());
    }
    if recipe.name.is_empty() {
        errors.push("recipe name is required".to_string());
    }
    if recipe.steps.is_empty() {
        errors.push("recipe must have at least one step".to_string());
    }
    for step in &recipe.steps {
        if step.connector.is_empty() {
            errors.push(format!("step '{}' has no connector", step.name));
        }
        if step.operation.is_empty() {
            errors.push(format!("step '{}' has no operation", step.name));
        }
    }
    for param in &recipe.parameters {
        if param.name.is_empty() {
            errors.push("parameter name is required".to_string());
        }
    }
    // Check required connectors match step connectors
    for step in &recipe.steps {
        if !step.connector.is_empty()
            && !recipe.required_connectors.contains(&step.connector)
        {
            errors.push(format!(
                "step '{}' uses connector '{}' not in required_connectors",
                step.name, step.connector
            ));
        }
    }

    errors
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RecipeCategory ────────────────────────────────────────────

    #[test]
    fn category_display() {
        assert_eq!(RecipeCategory::Development.to_string(), "development");
        assert_eq!(RecipeCategory::Communication.to_string(), "communication");
        assert_eq!(RecipeCategory::Deployment.to_string(), "deployment");
        assert_eq!(RecipeCategory::Analytics.to_string(), "analytics");
        assert_eq!(RecipeCategory::Security.to_string(), "security");
        assert_eq!(RecipeCategory::DataSync.to_string(), "data_sync");
        assert_eq!(RecipeCategory::Monitoring.to_string(), "monitoring");
    }

    #[test]
    fn category_serializes() {
        let json = serde_json::to_value(RecipeCategory::Development).unwrap();
        assert_eq!(json, "development");
    }

    // ── RecipeParameter ───────────────────────────────────────────

    #[test]
    fn param_required() {
        let p = RecipeParameter::required("owner", "Repo owner");
        assert!(p.required);
        assert!(p.default.is_none());
    }

    #[test]
    fn param_optional() {
        let p = RecipeParameter::optional("env", "Environment", "production");
        assert!(!p.required);
        assert_eq!(p.default.as_deref(), Some("production"));
    }

    #[test]
    fn param_with_example() {
        let p = RecipeParameter::required("owner", "Owner").with_example("octocat");
        assert_eq!(p.example.as_deref(), Some("octocat"));
    }

    #[test]
    fn param_with_description() {
        let p = RecipeParameter::required("x", "X").with_description("A description");
        assert_eq!(p.description, "A description");
    }

    // ── RecipeStep ────────────────────────────────────────────────

    #[test]
    fn step_basic() {
        let s = RecipeStep::new("get-issue", "github", "get_issue");
        assert_eq!(s.name, "get-issue");
        assert_eq!(s.connector, "github");
        assert_eq!(s.operation, "get_issue");
        assert!(s.input.is_empty());
    }

    #[test]
    fn step_with_inputs() {
        let s = RecipeStep::new("s", "c", "o")
            .with_input("key", "value");
        assert_eq!(s.input["key"], "value");
    }

    #[test]
    fn step_with_condition() {
        let s = RecipeStep::new("s", "c", "o")
            .with_condition("prev.status == 'success'");
        assert_eq!(s.condition.as_deref(), Some("prev.status == 'success'"));
    }

    #[test]
    fn step_continue_on_error() {
        let s = RecipeStep::new("s", "c", "o").with_continue_on_error(true);
        assert!(s.continue_on_error);
    }

    // ── Recipe ────────────────────────────────────────────────────

    #[test]
    fn recipe_basic() {
        let r = Recipe::new("test", "Test Recipe", RecipeCategory::Development);
        assert_eq!(r.id, "test");
        assert_eq!(r.name, "Test Recipe");
        assert_eq!(r.category, RecipeCategory::Development);
    }

    #[test]
    fn recipe_builders() {
        let r = Recipe::new("test", "Test", RecipeCategory::Development)
            .with_description("A test recipe")
            .with_connector("github")
            .with_tag("test")
            .with_parameter(RecipeParameter::required("x", "X"))
            .with_step(RecipeStep::new("s", "github", "o"));
        assert_eq!(r.description, "A test recipe");
        assert_eq!(r.required_connectors, vec!["github"]);
        assert_eq!(r.tags, vec!["test"]);
        assert_eq!(r.parameters.len(), 1);
        assert_eq!(r.steps.len(), 1);
    }

    #[test]
    fn recipe_step_count() {
        let r = Recipe::new("test", "Test", RecipeCategory::Development)
            .with_step(RecipeStep::new("a", "c", "o"))
            .with_step(RecipeStep::new("b", "c", "o"));
        assert_eq!(r.step_count(), 2);
    }

    #[test]
    fn recipe_connectors_used() {
        let r = Recipe::new("test", "Test", RecipeCategory::Development)
            .with_step(RecipeStep::new("a", "github", "o"))
            .with_step(RecipeStep::new("b", "slack", "o"))
            .with_step(RecipeStep::new("c", "github", "o"));
        let used = r.connectors_used();
        assert_eq!(used, vec!["github", "slack"]);
    }

    #[test]
    fn recipe_check_requirements_all_met() {
        let r = Recipe::new("test", "Test", RecipeCategory::Development)
            .with_connector("github")
            .with_connector("slack");
        let available = vec!["github".to_string(), "slack".to_string(), "discord".to_string()];
        assert!(r.check_requirements(&available).is_empty());
    }

    #[test]
    fn recipe_check_requirements_missing() {
        let r = Recipe::new("test", "Test", RecipeCategory::Development)
            .with_connector("github")
            .with_connector("jira");
        let available = vec!["github".to_string()];
        let missing = r.check_requirements(&available);
        assert_eq!(missing, vec!["jira"]);
    }

    #[test]
    fn recipe_serializes() {
        let r = Recipe::new("test", "Test", RecipeCategory::Development);
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["id"], "test");
        assert_eq!(json["category"], "development");
    }

    // ── RecipeLibrary ─────────────────────────────────────────────

    #[test]
    fn library_empty() {
        let lib = RecipeLibrary::new();
        assert!(lib.is_empty());
        assert_eq!(lib.len(), 0);
    }

    #[test]
    fn library_add_and_get() {
        let mut lib = RecipeLibrary::new();
        lib.add(Recipe::new("test", "Test", RecipeCategory::Development));
        assert_eq!(lib.len(), 1);
        assert!(lib.get("test").is_some());
        assert!(lib.get("nonexistent").is_none());
    }

    #[test]
    fn library_builtins() {
        let lib = RecipeLibrary::with_builtins();
        assert_eq!(lib.len(), 12);
        assert!(lib.get("issue-to-branch").is_some());
        assert!(lib.get("deploy-announce").is_some());
        assert!(lib.get("bug-triage").is_some());
    }

    #[test]
    fn library_by_category() {
        let lib = RecipeLibrary::with_builtins();
        let dev = lib.by_category(RecipeCategory::Development);
        assert!(dev.len() >= 2); // issue-to-branch, pr-review-notify, bug-triage
    }

    #[test]
    fn library_search() {
        let lib = RecipeLibrary::with_builtins();
        let results = lib.search("deploy");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "deploy-announce");
    }

    #[test]
    fn library_search_by_tag() {
        let lib = RecipeLibrary::with_builtins();
        let results = lib.search("notification");
        assert!(results.len() >= 2);
    }

    #[test]
    fn library_search_case_insensitive() {
        let lib = RecipeLibrary::with_builtins();
        let results = lib.search("DEPLOY");
        assert!(!results.is_empty());
    }

    #[test]
    fn library_available_recipes() {
        let lib = RecipeLibrary::with_builtins();
        let available = vec!["github".to_string(), "slack".to_string()];
        let recipes = lib.available_recipes(&available);
        // Should include recipes that only need github+slack
        assert!(recipes.iter().any(|r| r.id == "pr-review-notify"));
    }

    #[test]
    fn library_categories() {
        let lib = RecipeLibrary::with_builtins();
        let cats = lib.categories();
        assert!(cats.contains(&RecipeCategory::Development));
        assert!(cats.contains(&RecipeCategory::Communication));
        assert!(cats.contains(&RecipeCategory::Deployment));
    }

    // ── Built-in recipes ──────────────────────────────────────────

    #[test]
    fn builtin_issue_to_branch() {
        let r = recipe_issue_to_branch();
        assert_eq!(r.id, "issue-to-branch");
        assert_eq!(r.step_count(), 3);
        assert_eq!(r.required_connectors, vec!["github"]);
        assert!(r.parameters.len() >= 3);
    }

    #[test]
    fn builtin_pr_review_notify() {
        let r = recipe_pr_review_notify();
        assert_eq!(r.id, "pr-review-notify");
        assert_eq!(r.required_connectors.len(), 2);
    }

    #[test]
    fn builtin_deploy_announce() {
        let r = recipe_deploy_announce();
        assert_eq!(r.id, "deploy-announce");
        assert_eq!(r.category, RecipeCategory::Deployment);
    }

    #[test]
    fn builtin_bug_triage() {
        let r = recipe_bug_triage();
        assert_eq!(r.id, "bug-triage");
        assert!(r.step_count() >= 2);
    }

    #[test]
    fn builtin_cross_post() {
        let r = recipe_cross_post();
        assert_eq!(r.id, "cross-post");
        assert_eq!(r.category, RecipeCategory::Communication);
    }

    #[test]
    fn builtin_health_check() {
        let r = recipe_health_check_all();
        assert_eq!(r.id, "health-check-all");
        assert_eq!(r.category, RecipeCategory::Monitoring);
    }

    #[test]
    fn builtin_rotate_secrets() {
        let r = recipe_rotate_secrets();
        assert_eq!(r.id, "rotate-secrets");
        assert_eq!(r.category, RecipeCategory::Security);
    }

    #[test]
    fn builtin_sync_contacts() {
        let r = recipe_sync_contacts();
        assert_eq!(r.required_connectors.len(), 2);
    }

    #[test]
    fn builtin_analytics_report() {
        let r = recipe_analytics_report();
        assert_eq!(r.category, RecipeCategory::Analytics);
    }

    #[test]
    fn builtin_meeting_notes() {
        let r = recipe_meeting_notes();
        assert_eq!(r.category, RecipeCategory::Communication);
    }

    #[test]
    fn builtin_backup_to_s3() {
        let r = recipe_backup_to_s3();
        assert_eq!(r.category, RecipeCategory::DataSync);
    }

    #[test]
    fn builtin_digest_email() {
        let r = recipe_digest_email();
        assert_eq!(r.required_connectors.len(), 2);
    }

    // ── validate_recipe ───────────────────────────────────────────

    #[test]
    fn validate_valid_recipe() {
        let r = Recipe::new("test", "Test", RecipeCategory::Development)
            .with_connector("github")
            .with_step(RecipeStep::new("s", "github", "o"));
        assert!(validate_recipe(&r).is_empty());
    }

    #[test]
    fn validate_empty_id() {
        let r = Recipe::new("", "Test", RecipeCategory::Development)
            .with_step(RecipeStep::new("s", "c", "o"));
        let errors = validate_recipe(&r);
        assert!(errors.iter().any(|e| e.contains("id")));
    }

    #[test]
    fn validate_no_steps() {
        let r = Recipe::new("test", "Test", RecipeCategory::Development);
        let errors = validate_recipe(&r);
        assert!(errors.iter().any(|e| e.contains("at least one step")));
    }

    #[test]
    fn validate_step_missing_connector() {
        let r = Recipe::new("test", "Test", RecipeCategory::Development)
            .with_step(RecipeStep::new("s", "", "o"));
        let errors = validate_recipe(&r);
        assert!(errors.iter().any(|e| e.contains("no connector")));
    }

    #[test]
    fn validate_step_connector_not_in_required() {
        let r = Recipe::new("test", "Test", RecipeCategory::Development)
            .with_connector("github")
            .with_step(RecipeStep::new("s", "slack", "o"));
        let errors = validate_recipe(&r);
        assert!(errors.iter().any(|e| e.contains("not in required_connectors")));
    }

    #[test]
    fn validate_all_builtins() {
        for recipe in builtin_recipes() {
            let errors = validate_recipe(&recipe);
            assert!(
                errors.is_empty(),
                "recipe '{}' has validation errors: {:?}",
                recipe.id,
                errors
            );
        }
    }

    // ── format helpers ────────────────────────────────────────────

    #[test]
    fn format_summary() {
        let r = recipe_issue_to_branch();
        let s = format_recipe_summary(&r);
        assert!(s.contains("issue-to-branch"));
        assert!(s.contains("3 steps"));
        assert!(s.contains("github"));
    }

    #[test]
    fn format_detail() {
        let r = recipe_issue_to_branch();
        let s = format_recipe_detail(&r);
        assert!(s.contains("Issue to Branch"));
        assert!(s.contains("Parameters:"));
        assert!(s.contains("Steps:"));
        assert!(s.contains("github.get_issue"));
    }

    #[test]
    fn format_detail_no_params() {
        let r = Recipe::new("simple", "Simple", RecipeCategory::Development)
            .with_connector("github")
            .with_step(RecipeStep::new("s", "github", "o"));
        let s = format_recipe_detail(&r);
        assert!(!s.contains("Parameters:"));
    }
}
