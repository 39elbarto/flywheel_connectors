//! Onboarding and repair command family for `fwc setup`.
//!
//! Provides environment health checks, automated repair, project
//! initialization, and component status overview. Each subcommand maps
//! to a distinct workflow:
//!
//! ```text
//! fwc setup check              # diagnose all components
//! fwc setup check --component host
//! fwc setup repair --auto-fix  # apply safe fixes
//! fwc setup repair --dry-run   # preview only
//! fwc setup init my-project    # scaffold new project
//! fwc setup status             # quick health summary
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

// ── SetupComponent ──────────────────────────────────────────────────

/// Infrastructure component that can be checked, repaired, or reported on.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupComponent {
    /// FCP host process and runtime environment.
    Host,
    /// Credential store and authentication configuration.
    Credentials,
    /// Active project context (working directory, config files).
    Context,
    /// Mesh network and peer discovery.
    Mesh,
    /// Outbound network connectivity to upstream APIs.
    Connectivity,
    /// Connector runtime (binary availability, versions).
    Runtime,
}

impl SetupComponent {
    /// All component variants in dependency order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::Host,
            Self::Runtime,
            Self::Connectivity,
            Self::Credentials,
            Self::Context,
            Self::Mesh,
        ]
    }

    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Credentials => "credentials",
            Self::Context => "context",
            Self::Mesh => "mesh",
            Self::Connectivity => "connectivity",
            Self::Runtime => "runtime",
        }
    }

    /// Descriptive name for display.
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Host => "FCP Host",
            Self::Credentials => "Credential Store",
            Self::Context => "Project Context",
            Self::Mesh => "Mesh Network",
            Self::Connectivity => "Network Connectivity",
            Self::Runtime => "Connector Runtime",
        }
    }

    /// Components this one depends on.
    pub const fn dependencies(self) -> &'static [Self] {
        match self {
            Self::Host | Self::Connectivity => &[],
            Self::Runtime | Self::Credentials | Self::Context => &[Self::Host],
            Self::Mesh => &[Self::Host, Self::Connectivity],
        }
    }

    /// Parse from string (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "host" => Some(Self::Host),
            "credentials" | "creds" | "credential" => Some(Self::Credentials),
            "context" | "ctx" => Some(Self::Context),
            "mesh" => Some(Self::Mesh),
            "connectivity" | "network" | "net" => Some(Self::Connectivity),
            "runtime" | "rt" => Some(Self::Runtime),
            _ => None,
        }
    }
}

impl std::fmt::Display for SetupComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl std::str::FromStr for SetupComponent {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| format!("unknown component: {s}"))
    }
}

// ── Component health ────────────────────────────────────────────────

/// Health status for a single component.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    /// Component is fully operational.
    Healthy,
    /// Component is working but with warnings.
    Degraded,
    /// Component is not installed or not configured.
    Missing,
    /// Component encountered an error.
    Error,
}

impl ComponentStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Missing => "missing",
            Self::Error => "error",
        }
    }

    /// Whether this status indicates a problem.
    pub const fn is_problem(self) -> bool {
        matches!(self, Self::Degraded | Self::Missing | Self::Error)
    }

    /// Whether this status means the component is usable at all.
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }
}

impl std::fmt::Display for ComponentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Health assessment for a single component.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Which component was assessed.
    pub component: SetupComponent,
    /// Current status.
    pub status: ComponentStatus,
    /// Human-readable status message.
    pub message: String,
    /// Suggested remediation (if status is not Healthy).
    pub remediation: Option<String>,
}

impl ComponentHealth {
    /// Create a healthy assessment.
    pub fn healthy(component: SetupComponent) -> Self {
        Self {
            component,
            status: ComponentStatus::Healthy,
            message: format!("{} is operational", component.display_name()),
            remediation: None,
        }
    }

    /// Create a degraded assessment.
    pub fn degraded(
        component: SetupComponent,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            component,
            status: ComponentStatus::Degraded,
            message: message.into(),
            remediation: Some(remediation.into()),
        }
    }

    /// Create a missing assessment.
    pub fn missing(
        component: SetupComponent,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            component,
            status: ComponentStatus::Missing,
            message: message.into(),
            remediation: Some(remediation.into()),
        }
    }

    /// Create an error assessment.
    pub fn error(
        component: SetupComponent,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            component,
            status: ComponentStatus::Error,
            message: message.into(),
            remediation: Some(remediation.into()),
        }
    }

    /// Whether this assessment indicates a problem.
    pub const fn has_problem(&self) -> bool {
        self.status.is_problem()
    }

    /// Render as structured JSON value.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

// ── Overall status ──────────────────────────────────────────────────

/// Aggregate status computed from all component health assessments.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallStatus {
    /// All components healthy.
    Ready,
    /// Some components degraded but usable.
    PartiallyReady,
    /// Critical components missing or errored.
    NotReady,
}

impl OverallStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::PartiallyReady => "partially_ready",
            Self::NotReady => "not_ready",
        }
    }
}

impl std::fmt::Display for OverallStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ── Command argument types ──────────────────────────────────────────

/// Arguments for `fwc setup check`.
#[derive(Clone, Debug)]
pub struct SetupCheckArgs {
    /// Only check this specific component.
    pub component: Option<SetupComponent>,
    /// Show detailed diagnostic output.
    pub verbose: bool,
}

impl SetupCheckArgs {
    pub const fn new() -> Self {
        Self {
            component: None,
            verbose: false,
        }
    }

    pub const fn with_component(mut self, component: SetupComponent) -> Self {
        self.component = Some(component);
        self
    }

    pub const fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }
}

impl Default for SetupCheckArgs {
    fn default() -> Self {
        Self::new()
    }
}

/// Arguments for `fwc setup repair`.
#[derive(Clone, Debug)]
pub struct SetupRepairArgs {
    /// Only repair this specific component.
    pub component: Option<SetupComponent>,
    /// Automatically apply safe fixes without confirmation.
    pub auto_fix: bool,
    /// Preview repairs without applying.
    pub dry_run: bool,
}

impl SetupRepairArgs {
    pub const fn new() -> Self {
        Self {
            component: None,
            auto_fix: false,
            dry_run: false,
        }
    }

    pub const fn with_component(mut self, component: SetupComponent) -> Self {
        self.component = Some(component);
        self
    }

    pub const fn with_auto_fix(mut self, auto_fix: bool) -> Self {
        self.auto_fix = auto_fix;
        self
    }

    pub const fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }
}

impl Default for SetupRepairArgs {
    fn default() -> Self {
        Self::new()
    }
}

/// Arguments for `fwc setup init`.
#[derive(Clone, Debug)]
pub struct SetupInitArgs {
    /// Name of the project to create.
    pub project_name: String,
    /// Template to use for scaffolding.
    pub template: Option<String>,
    /// Overwrite existing project files.
    pub force: bool,
}

impl SetupInitArgs {
    pub fn new(project_name: impl Into<String>) -> Self {
        Self {
            project_name: project_name.into(),
            template: None,
            force: false,
        }
    }

    pub fn with_template(mut self, template: impl Into<String>) -> Self {
        self.template = Some(template.into());
        self
    }

    pub const fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }
}

/// Arguments for `fwc setup status`.
#[derive(Clone, Debug)]
pub struct SetupStatusArgs {
    /// Only show this specific component.
    pub component: Option<SetupComponent>,
}

impl SetupStatusArgs {
    pub const fn new() -> Self {
        Self { component: None }
    }

    pub const fn with_component(mut self, component: SetupComponent) -> Self {
        self.component = Some(component);
        self
    }
}

impl Default for SetupStatusArgs {
    fn default() -> Self {
        Self::new()
    }
}

// ── Check result ────────────────────────────────────────────────────

/// Result of a full setup check.
#[derive(Clone, Debug, Serialize)]
pub struct SetupCheckResult {
    /// Individual component health assessments.
    pub components: Vec<ComponentHealth>,
    /// Computed overall status.
    pub overall_status: OverallStatus,
    /// Actionable recommendations.
    pub recommendations: Vec<String>,
}

impl SetupCheckResult {
    /// Build a check result from component health assessments.
    pub fn from_components(components: Vec<ComponentHealth>) -> Self {
        let overall_status = compute_overall_status(&components);
        let recommendations = generate_recommendations(&components);
        Self {
            components,
            overall_status,
            recommendations,
        }
    }

    /// Number of healthy components.
    pub fn healthy_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.status == ComponentStatus::Healthy)
            .count()
    }

    /// Number of components with problems.
    pub fn problem_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.status.is_problem())
            .count()
    }

    /// Total number of components assessed.
    pub fn total_count(&self) -> usize {
        self.components.len()
    }

    /// Whether all components are healthy.
    pub fn all_healthy(&self) -> bool {
        self.components.iter().all(|c| !c.status.is_problem())
    }

    /// Find the health entry for a specific component.
    pub fn get_component(&self, component: SetupComponent) -> Option<&ComponentHealth> {
        self.components.iter().find(|c| c.component == component)
    }

    /// Render as structured JSON value.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

// ── Repair types ────────────────────────────────────────────────────

/// Type of repair action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairActionType {
    /// Install a missing component.
    Install,
    /// Reconfigure an existing component.
    Reconfigure,
    /// Restart a stopped/hung component.
    Restart,
    /// Clear cache or stale state.
    ClearState,
    /// Create missing directory or file.
    CreateResource,
    /// Update a component to a newer version.
    Update,
}

impl RepairActionType {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Reconfigure => "reconfigure",
            Self::Restart => "restart",
            Self::ClearState => "clear_state",
            Self::CreateResource => "create_resource",
            Self::Update => "update",
        }
    }
}

impl std::fmt::Display for RepairActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A single repair action that can be applied.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepairAction {
    /// Component this action targets.
    pub component: SetupComponent,
    /// Type of repair.
    pub action_type: RepairActionType,
    /// Human-readable description.
    pub description: String,
    /// Whether this action can be undone.
    pub reversible: bool,
    /// Whether this action was applied (vs. skipped/dry-run).
    pub applied: bool,
}

impl RepairAction {
    /// Create a new repair action (not yet applied).
    pub fn new(
        component: SetupComponent,
        action_type: RepairActionType,
        description: impl Into<String>,
    ) -> Self {
        Self {
            component,
            action_type,
            description: description.into(),
            reversible: true,
            applied: false,
        }
    }

    /// Mark as irreversible.
    pub const fn irreversible(mut self) -> Self {
        self.reversible = false;
        self
    }

    /// Mark as applied.
    pub const fn mark_applied(&mut self) {
        self.applied = true;
    }

    /// Whether this is safe for auto-fix (reversible actions only).
    pub const fn is_auto_safe(&self) -> bool {
        self.reversible
    }
}

/// Result of a repair operation.
#[derive(Clone, Debug, Serialize)]
pub struct RepairResult {
    /// All repair actions (applied and skipped).
    pub actions: Vec<RepairAction>,
    /// Number of successfully applied actions.
    pub success_count: usize,
    /// Number of failed actions.
    pub failure_count: usize,
    /// Number of skipped actions (dry-run or not auto-safe).
    pub skipped_count: usize,
}

impl RepairResult {
    /// Create from a list of repair actions.
    pub fn from_actions(actions: Vec<RepairAction>) -> Self {
        let success_count = actions.iter().filter(|a| a.applied).count();
        let failure_count = 0; // failures tracked separately
        let skipped_count = actions.iter().filter(|a| !a.applied).count();
        Self {
            actions,
            success_count,
            failure_count,
            skipped_count,
        }
    }

    /// Create with explicit failure count.
    pub fn with_failures(actions: Vec<RepairAction>, failure_count: usize) -> Self {
        let success_count = actions.iter().filter(|a| a.applied).count();
        let skipped_count = actions.len().saturating_sub(success_count + failure_count);
        Self {
            actions,
            success_count,
            failure_count,
            skipped_count,
        }
    }

    /// Total number of actions.
    pub fn total_count(&self) -> usize {
        self.actions.len()
    }

    /// Whether all actions succeeded.
    pub fn all_succeeded(&self) -> bool {
        self.failure_count == 0 && self.skipped_count == 0 && !self.actions.is_empty()
    }

    /// Whether no actions were needed.
    pub fn nothing_to_do(&self) -> bool {
        self.actions.is_empty()
    }

    /// Render as JSON.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

// ── Init result ─────────────────────────────────────────────────────

/// Result of project initialization.
#[derive(Clone, Debug, Serialize)]
pub struct InitResult {
    /// Path to the created project directory.
    pub project_path: PathBuf,
    /// Config files created during initialization.
    pub config_files_created: Vec<String>,
    /// Next steps for the user.
    pub next_steps: Vec<String>,
}

impl InitResult {
    /// Create a new init result.
    pub const fn new(project_path: PathBuf) -> Self {
        Self {
            project_path,
            config_files_created: Vec::new(),
            next_steps: Vec::new(),
        }
    }

    /// Add a config file to the list.
    pub fn add_config_file(&mut self, file: impl Into<String>) {
        self.config_files_created.push(file.into());
    }

    /// Add a next step.
    pub fn add_next_step(&mut self, step: impl Into<String>) {
        self.next_steps.push(step.into());
    }

    /// Number of files created.
    pub fn file_count(&self) -> usize {
        self.config_files_created.len()
    }

    /// Render as JSON.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

// ── Core functions ──────────────────────────────────────────────────

/// Compute overall status from individual component health entries.
fn compute_overall_status(components: &[ComponentHealth]) -> OverallStatus {
    if components.is_empty() {
        return OverallStatus::NotReady;
    }

    let has_error = components
        .iter()
        .any(|c| c.status == ComponentStatus::Error);
    let has_missing = components
        .iter()
        .any(|c| c.status == ComponentStatus::Missing);
    let has_degraded = components
        .iter()
        .any(|c| c.status == ComponentStatus::Degraded);

    // Critical components (Host, Runtime) must be healthy or at least degraded.
    let critical_ok = components
        .iter()
        .filter(|c| matches!(c.component, SetupComponent::Host | SetupComponent::Runtime))
        .all(|c| c.status.is_usable());

    if has_error || (has_missing && !critical_ok) {
        OverallStatus::NotReady
    } else if has_degraded || has_missing {
        OverallStatus::PartiallyReady
    } else {
        OverallStatus::Ready
    }
}

/// Generate actionable recommendations from component health.
fn generate_recommendations(components: &[ComponentHealth]) -> Vec<String> {
    let mut recs = Vec::new();

    for ch in components {
        match (ch.component, ch.status) {
            (SetupComponent::Host, ComponentStatus::Missing) => {
                recs.push("Install and start the FCP host: `fwc host start`".to_owned());
            }
            (SetupComponent::Host, ComponentStatus::Error) => {
                recs.push("Restart the FCP host: `fwc host restart`".to_owned());
            }
            (SetupComponent::Credentials, ComponentStatus::Missing) => {
                recs.push(
                    "Configure credentials: `fwc auth add <connector> --token <TOKEN>`".to_owned(),
                );
            }
            (SetupComponent::Credentials, ComponentStatus::Degraded) => {
                recs.push("Some credentials may be expired: `fwc auth status`".to_owned());
            }
            (SetupComponent::Context, ComponentStatus::Missing) => {
                recs.push(
                    "Initialize a project context: `fwc setup init <project-name>`".to_owned(),
                );
            }
            (SetupComponent::Mesh, ComponentStatus::Missing) => {
                recs.push("Configure mesh peers: `fwc mesh configure`".to_owned());
            }
            (SetupComponent::Mesh, ComponentStatus::Degraded) => {
                recs.push("Some mesh peers are unreachable: `fwc mesh status`".to_owned());
            }
            (SetupComponent::Connectivity, ComponentStatus::Error) => {
                recs.push("Check network connectivity and proxy settings".to_owned());
            }
            (SetupComponent::Runtime, ComponentStatus::Missing) => {
                recs.push("Install connector runtimes: `fwc install`".to_owned());
            }
            (SetupComponent::Runtime, ComponentStatus::Degraded) => {
                recs.push("Update connector runtimes: `fwc update`".to_owned());
            }
            _ => {}
        }
    }

    if recs.is_empty()
        && components
            .iter()
            .all(|c| c.status == ComponentStatus::Healthy)
    {
        recs.push("All components are healthy. No action needed.".to_owned());
    }

    recs
}

/// Check the setup environment, optionally filtering to a single component.
pub fn check_setup(args: &SetupCheckArgs) -> SetupCheckResult {
    let targets: Vec<SetupComponent> = args
        .component
        .map_or_else(|| SetupComponent::all().to_vec(), |c| vec![c]);

    let components: Vec<ComponentHealth> = targets
        .iter()
        .map(|c| check_component(*c, args.verbose))
        .collect();

    SetupCheckResult::from_components(components)
}

/// Check health for a single component.
fn check_component(component: SetupComponent, verbose: bool) -> ComponentHealth {
    // In a real implementation this would probe the actual system.
    // For now we return a simulated result based on the component type.
    // The verbose flag would add extra diagnostic detail.
    let _ = verbose;

    // Check dependencies first.
    for dep in component.dependencies() {
        let dep_health = check_component_basic(*dep);
        if dep_health.status == ComponentStatus::Missing
            || dep_health.status == ComponentStatus::Error
        {
            return ComponentHealth::degraded(
                component,
                format!(
                    "{} depends on {} which is {}",
                    component.display_name(),
                    dep.display_name(),
                    dep_health.status
                ),
                format!(
                    "Fix {} first: `fwc setup repair --component {}`",
                    dep.display_name(),
                    dep.label()
                ),
            );
        }
    }

    ComponentHealth::healthy(component)
}

/// Quick basic check without dependency traversal (prevents infinite recursion).
fn check_component_basic(component: SetupComponent) -> ComponentHealth {
    // Stub: real implementation would do actual probes.
    ComponentHealth::healthy(component)
}

/// Simulate component checks from pre-built health data (for testing/scripting).
pub fn check_setup_with_health(
    health_map: &BTreeMap<SetupComponent, ComponentHealth>,
) -> SetupCheckResult {
    let components: Vec<ComponentHealth> = SetupComponent::all()
        .iter()
        .map(|c| {
            health_map
                .get(c)
                .cloned()
                .unwrap_or_else(|| ComponentHealth::healthy(*c))
        })
        .collect();

    SetupCheckResult::from_components(components)
}

/// Repair degraded/missing components.
pub fn repair_setup(args: &SetupRepairArgs, check_result: &SetupCheckResult) -> RepairResult {
    let targets: Vec<&ComponentHealth> = check_result
        .components
        .iter()
        .filter(|c| c.status.is_problem())
        .filter(|c| args.component.is_none() || args.component == Some(c.component))
        .collect();

    if targets.is_empty() {
        return RepairResult::from_actions(Vec::new());
    }

    let mut actions: Vec<RepairAction> = Vec::new();

    for ch in &targets {
        let repair = plan_repair(ch);
        actions.extend(repair);
    }

    if args.dry_run {
        // In dry-run mode, nothing is applied.
        return RepairResult::from_actions(actions);
    }

    if args.auto_fix {
        // Apply only auto-safe (reversible) actions.
        for action in &mut actions {
            if action.is_auto_safe() {
                // In a real implementation, we would execute the repair here.
                action.mark_applied();
            }
        }
    } else {
        // Without auto_fix, apply all actions (user confirmed).
        for action in &mut actions {
            action.mark_applied();
        }
    }

    RepairResult::from_actions(actions)
}

/// Plan repair actions for a component.
fn plan_repair(health: &ComponentHealth) -> Vec<RepairAction> {
    if health.status == ComponentStatus::Healthy {
        return Vec::new();
    }
    match health.component {
        SetupComponent::Host => plan_repair_host(health.status),
        SetupComponent::Credentials => plan_repair_credentials(health.status),
        SetupComponent::Context => plan_repair_context(health.status),
        SetupComponent::Mesh => plan_repair_mesh(health.status),
        SetupComponent::Connectivity => plan_repair_connectivity(health.status),
        SetupComponent::Runtime => plan_repair_runtime(health.status),
    }
}

fn plan_repair_host(status: ComponentStatus) -> Vec<RepairAction> {
    match status {
        ComponentStatus::Missing => vec![RepairAction::new(
            SetupComponent::Host,
            RepairActionType::Install,
            "Install FCP host runtime",
        )],
        ComponentStatus::Error => vec![RepairAction::new(
            SetupComponent::Host,
            RepairActionType::Restart,
            "Restart FCP host process",
        )],
        ComponentStatus::Degraded => vec![RepairAction::new(
            SetupComponent::Host,
            RepairActionType::Reconfigure,
            "Reconfigure FCP host settings",
        )],
        ComponentStatus::Healthy => Vec::new(),
    }
}

fn plan_repair_credentials(status: ComponentStatus) -> Vec<RepairAction> {
    match status {
        ComponentStatus::Missing => vec![RepairAction::new(
            SetupComponent::Credentials,
            RepairActionType::CreateResource,
            "Initialize credential store",
        )],
        ComponentStatus::Degraded => vec![RepairAction::new(
            SetupComponent::Credentials,
            RepairActionType::Reconfigure,
            "Refresh expired credentials",
        )],
        ComponentStatus::Error => vec![RepairAction::new(
            SetupComponent::Credentials,
            RepairActionType::Reconfigure,
            "Repair credential store",
        )],
        ComponentStatus::Healthy => Vec::new(),
    }
}

fn plan_repair_context(status: ComponentStatus) -> Vec<RepairAction> {
    match status {
        ComponentStatus::Missing => vec![
            RepairAction::new(
                SetupComponent::Context,
                RepairActionType::CreateResource,
                "Create project context directory",
            ),
            RepairAction::new(
                SetupComponent::Context,
                RepairActionType::CreateResource,
                "Generate default configuration files",
            ),
        ],
        ComponentStatus::Error => vec![RepairAction::new(
            SetupComponent::Context,
            RepairActionType::ClearState,
            "Clear corrupted context state",
        )],
        ComponentStatus::Degraded => vec![RepairAction::new(
            SetupComponent::Context,
            RepairActionType::Reconfigure,
            "Repair context configuration",
        )],
        ComponentStatus::Healthy => Vec::new(),
    }
}

fn plan_repair_mesh(status: ComponentStatus) -> Vec<RepairAction> {
    match status {
        ComponentStatus::Missing => vec![RepairAction::new(
            SetupComponent::Mesh,
            RepairActionType::Install,
            "Initialize mesh network configuration",
        )],
        ComponentStatus::Degraded => vec![RepairAction::new(
            SetupComponent::Mesh,
            RepairActionType::Restart,
            "Restart mesh peer discovery",
        )],
        ComponentStatus::Error => vec![RepairAction::new(
            SetupComponent::Mesh,
            RepairActionType::Reconfigure,
            "Repair mesh configuration",
        )],
        ComponentStatus::Healthy => Vec::new(),
    }
}

fn plan_repair_connectivity(status: ComponentStatus) -> Vec<RepairAction> {
    match status {
        ComponentStatus::Error => vec![
            RepairAction::new(
                SetupComponent::Connectivity,
                RepairActionType::Reconfigure,
                "Reset network proxy configuration",
            )
            .irreversible(),
        ],
        ComponentStatus::Degraded => vec![RepairAction::new(
            SetupComponent::Connectivity,
            RepairActionType::ClearState,
            "Clear DNS cache",
        )],
        ComponentStatus::Missing => vec![RepairAction::new(
            SetupComponent::Connectivity,
            RepairActionType::Reconfigure,
            "Configure network settings",
        )],
        ComponentStatus::Healthy => Vec::new(),
    }
}

fn plan_repair_runtime(status: ComponentStatus) -> Vec<RepairAction> {
    match status {
        ComponentStatus::Missing => vec![RepairAction::new(
            SetupComponent::Runtime,
            RepairActionType::Install,
            "Install connector runtime binaries",
        )],
        ComponentStatus::Degraded => vec![RepairAction::new(
            SetupComponent::Runtime,
            RepairActionType::Update,
            "Update connector runtimes to latest version",
        )],
        ComponentStatus::Error => vec![RepairAction::new(
            SetupComponent::Runtime,
            RepairActionType::Restart,
            "Restart connector runtime",
        )],
        ComponentStatus::Healthy => Vec::new(),
    }
}

/// Initialize a new FCP project.
pub fn init_setup(args: &SetupInitArgs) -> Result<InitResult, InitError> {
    // Validate project name.
    if args.project_name.is_empty() {
        return Err(InitError::InvalidName(
            "Project name cannot be empty".to_owned(),
        ));
    }

    if args.project_name.len() > 128 {
        return Err(InitError::InvalidName(
            "Project name exceeds 128 characters".to_owned(),
        ));
    }

    if !args
        .project_name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(InitError::InvalidName(
            "Project name must contain only alphanumeric characters, hyphens, underscores, or dots"
                .to_owned(),
        ));
    }

    let project_path = PathBuf::from(&args.project_name);

    // Check if project already exists.
    if project_path.exists() && !args.force {
        return Err(InitError::AlreadyExists(project_path));
    }

    let template = args.template.as_deref().unwrap_or("default");

    let config_files = generate_config_files(template);

    let mut result = InitResult::new(project_path);
    for file in &config_files {
        result.add_config_file(file.clone());
    }

    // Generate next steps based on template.
    result.add_next_step(format!("cd {}", args.project_name));
    result.add_next_step("fwc auth add <connector> --token <TOKEN>".to_owned());
    result.add_next_step("fwc setup check".to_owned());

    if template == "mesh" {
        result.add_next_step("fwc mesh configure".to_owned());
    }

    Ok(result)
}

/// Errors that can occur during project initialization.
#[derive(Clone, Debug)]
pub enum InitError {
    /// Project name is invalid.
    InvalidName(String),
    /// Project directory already exists (and --force not set).
    AlreadyExists(PathBuf),
    /// Template not found.
    UnknownTemplate(String),
    /// I/O error during file creation.
    IoError(String),
}

impl std::fmt::Display for InitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName(msg) => write!(f, "invalid project name: {msg}"),
            Self::AlreadyExists(path) => {
                write!(f, "project already exists: {}", path.display())
            }
            Self::UnknownTemplate(name) => write!(f, "unknown template: {name}"),
            Self::IoError(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

/// Generate config file names for a given template.
fn generate_config_files(template: &str) -> Vec<String> {
    let mut files = vec!["fcp.toml".to_owned(), ".fcp/config.json".to_owned()];

    match template {
        "default" => {
            files.push(".fcp/credentials.json".to_owned());
        }
        "mesh" => {
            files.push(".fcp/credentials.json".to_owned());
            files.push(".fcp/mesh.toml".to_owned());
            files.push(".fcp/peers.json".to_owned());
        }
        "full" => {
            files.push(".fcp/credentials.json".to_owned());
            files.push(".fcp/mesh.toml".to_owned());
            files.push(".fcp/peers.json".to_owned());
            files.push(".fcp/policies.toml".to_owned());
            files.push(".fcp/zones.json".to_owned());
        }
        // "minimal" and unknown templates get only the base files.
        _ => {}
    }

    files
}

/// Quick status check — returns component health summary.
pub fn setup_status(args: &SetupStatusArgs) -> SetupCheckResult {
    let check_args = SetupCheckArgs {
        component: args.component,
        verbose: false,
    };
    check_setup(&check_args)
}

// ── TOON formatting ─────────────────────────────────────────────────

/// Format a check result as TOON output lines.
pub fn format_check_toon(result: &SetupCheckResult) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(format!(
        "Setup Check: {} ({}/{})",
        result.overall_status,
        result.healthy_count(),
        result.total_count()
    ));
    lines.push(String::new());

    for ch in &result.components {
        let status_indicator = match ch.status {
            ComponentStatus::Healthy => "[OK]",
            ComponentStatus::Degraded => "[!!]",
            ComponentStatus::Missing => "[--]",
            ComponentStatus::Error => "[XX]",
        };
        lines.push(format!(
            "  {} {:<25} {}",
            status_indicator,
            ch.component.display_name(),
            ch.message
        ));
        if let Some(ref rem) = ch.remediation {
            lines.push(format!("     Remedy: {rem}"));
        }
    }

    if !result.recommendations.is_empty() {
        lines.push(String::new());
        lines.push("Recommendations:".to_owned());
        for rec in &result.recommendations {
            lines.push(format!("  - {rec}"));
        }
    }

    lines
}

/// Format a repair result as TOON output lines.
pub fn format_repair_toon(result: &RepairResult) -> Vec<String> {
    let mut lines = Vec::new();

    if result.nothing_to_do() {
        lines.push("Repair: nothing to do — all components healthy.".to_owned());
        return lines;
    }

    lines.push(format!(
        "Repair: {} actions ({} applied, {} failed, {} skipped)",
        result.total_count(),
        result.success_count,
        result.failure_count,
        result.skipped_count,
    ));
    lines.push(String::new());

    for action in &result.actions {
        let status = if action.applied { "[DONE]" } else { "[SKIP]" };
        let reversible = if action.reversible {
            ""
        } else {
            " (irreversible)"
        };
        lines.push(format!(
            "  {} {:<12} {:<25} {}{}",
            status,
            action.action_type,
            action.component.display_name(),
            action.description,
            reversible,
        ));
    }

    lines
}

/// Format an init result as TOON output lines.
pub fn format_init_toon(result: &InitResult) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(format!(
        "Project initialized: {}",
        result.project_path.display()
    ));
    lines.push(String::new());

    if !result.config_files_created.is_empty() {
        lines.push(format!("Files created ({}):", result.file_count()));
        for file in &result.config_files_created {
            lines.push(format!("  + {file}"));
        }
    }

    if !result.next_steps.is_empty() {
        lines.push(String::new());
        lines.push("Next steps:".to_owned());
        for (i, step) in result.next_steps.iter().enumerate() {
            lines.push(format!("  {}. {step}", i + 1));
        }
    }

    lines
}

/// Format a status summary as TOON output lines.
pub fn format_status_toon(result: &SetupCheckResult) -> Vec<String> {
    let mut lines = Vec::new();

    let emoji = match result.overall_status {
        OverallStatus::Ready => "READY",
        OverallStatus::PartiallyReady => "PARTIAL",
        OverallStatus::NotReady => "NOT READY",
    };

    lines.push(format!("Status: {emoji}"));

    for ch in &result.components {
        let dot = match ch.status {
            ComponentStatus::Healthy => "+",
            ComponentStatus::Degraded => "~",
            ComponentStatus::Missing => "-",
            ComponentStatus::Error => "!",
        };
        lines.push(format!("  {dot} {}", ch.component.display_name()));
    }

    lines
}

/// Format an init error as TOON output lines.
pub fn format_init_error_toon(error: &InitError) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!("Init failed: {error}"));

    match error {
        InitError::InvalidName(_) => {
            lines.push(
                "  Use only alphanumeric characters, hyphens, underscores, or dots.".to_owned(),
            );
        }
        InitError::AlreadyExists(path) => {
            lines.push(format!(
                "  Directory {} already exists. Use --force to overwrite.",
                path.display()
            ));
        }
        InitError::UnknownTemplate(name) => {
            lines.push("  Available templates: default, minimal, mesh, full".to_owned());
            lines.push(format!("  Unknown template: {name}"));
        }
        InitError::IoError(_) => {
            lines.push("  Check file system permissions and available disk space.".to_owned());
        }
    }

    lines
}

/// Return the dependency-ordered list of components for repair sequencing.
pub fn repair_order() -> Vec<SetupComponent> {
    // Topological order based on dependencies.
    vec![
        SetupComponent::Host,
        SetupComponent::Connectivity,
        SetupComponent::Runtime,
        SetupComponent::Credentials,
        SetupComponent::Context,
        SetupComponent::Mesh,
    ]
}

/// Validate that a given template name is known.
pub fn is_known_template(name: &str) -> bool {
    matches!(name, "default" | "minimal" | "mesh" | "full")
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SetupComponent ──────────────────────────────────────────────

    #[test]
    fn component_all_returns_six() {
        assert_eq!(SetupComponent::all().len(), 6);
    }

    #[test]
    fn component_labels() {
        assert_eq!(SetupComponent::Host.label(), "host");
        assert_eq!(SetupComponent::Credentials.label(), "credentials");
        assert_eq!(SetupComponent::Context.label(), "context");
        assert_eq!(SetupComponent::Mesh.label(), "mesh");
        assert_eq!(SetupComponent::Connectivity.label(), "connectivity");
        assert_eq!(SetupComponent::Runtime.label(), "runtime");
    }

    #[test]
    fn component_display_names() {
        assert_eq!(SetupComponent::Host.display_name(), "FCP Host");
        assert_eq!(
            SetupComponent::Credentials.display_name(),
            "Credential Store"
        );
        assert_eq!(SetupComponent::Context.display_name(), "Project Context");
        assert_eq!(SetupComponent::Mesh.display_name(), "Mesh Network");
        assert_eq!(
            SetupComponent::Connectivity.display_name(),
            "Network Connectivity"
        );
        assert_eq!(SetupComponent::Runtime.display_name(), "Connector Runtime");
    }

    #[test]
    fn component_display_trait() {
        assert_eq!(format!("{}", SetupComponent::Host), "host");
        assert_eq!(format!("{}", SetupComponent::Mesh), "mesh");
    }

    #[test]
    fn component_parse_canonical() {
        assert_eq!(SetupComponent::parse("host"), Some(SetupComponent::Host));
        assert_eq!(
            SetupComponent::parse("credentials"),
            Some(SetupComponent::Credentials)
        );
        assert_eq!(
            SetupComponent::parse("context"),
            Some(SetupComponent::Context)
        );
        assert_eq!(SetupComponent::parse("mesh"), Some(SetupComponent::Mesh));
        assert_eq!(
            SetupComponent::parse("connectivity"),
            Some(SetupComponent::Connectivity)
        );
        assert_eq!(
            SetupComponent::parse("runtime"),
            Some(SetupComponent::Runtime)
        );
    }

    #[test]
    fn component_parse_aliases() {
        assert_eq!(
            SetupComponent::parse("creds"),
            Some(SetupComponent::Credentials)
        );
        assert_eq!(
            SetupComponent::parse("credential"),
            Some(SetupComponent::Credentials)
        );
        assert_eq!(SetupComponent::parse("ctx"), Some(SetupComponent::Context));
        assert_eq!(
            SetupComponent::parse("network"),
            Some(SetupComponent::Connectivity)
        );
        assert_eq!(
            SetupComponent::parse("net"),
            Some(SetupComponent::Connectivity)
        );
        assert_eq!(SetupComponent::parse("rt"), Some(SetupComponent::Runtime));
    }

    #[test]
    fn component_parse_case_insensitive() {
        assert_eq!(SetupComponent::parse("HOST"), Some(SetupComponent::Host));
        assert_eq!(SetupComponent::parse("Mesh"), Some(SetupComponent::Mesh));
        assert_eq!(
            SetupComponent::parse("RUNTIME"),
            Some(SetupComponent::Runtime)
        );
    }

    #[test]
    fn component_parse_unknown() {
        assert_eq!(SetupComponent::parse("bogus"), None);
        assert_eq!(SetupComponent::parse(""), None);
    }

    #[test]
    fn component_from_str() {
        let c: Result<SetupComponent, _> = "host".parse();
        assert_eq!(c.unwrap(), SetupComponent::Host);

        let c: Result<SetupComponent, _> = "unknown".parse();
        assert!(c.is_err());
    }

    #[test]
    fn component_dependencies_host_has_none() {
        assert!(SetupComponent::Host.dependencies().is_empty());
    }

    #[test]
    fn component_dependencies_runtime_depends_on_host() {
        let deps = SetupComponent::Runtime.dependencies();
        assert!(deps.contains(&SetupComponent::Host));
    }

    #[test]
    fn component_dependencies_mesh_depends_on_host_and_connectivity() {
        let deps = SetupComponent::Mesh.dependencies();
        assert!(deps.contains(&SetupComponent::Host));
        assert!(deps.contains(&SetupComponent::Connectivity));
    }

    #[test]
    fn component_dependencies_connectivity_has_none() {
        assert!(SetupComponent::Connectivity.dependencies().is_empty());
    }

    #[test]
    fn component_ord_is_consistent() {
        let mut v = [
            SetupComponent::Mesh,
            SetupComponent::Host,
            SetupComponent::Context,
        ];
        v.sort();
        // Just verify sorting does not panic and produces deterministic order.
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn component_serialize_json() {
        let json = serde_json::to_string(&SetupComponent::Host).unwrap();
        assert_eq!(json, r#""host""#);
    }

    #[test]
    fn component_deserialize_json() {
        let c: SetupComponent = serde_json::from_str(r#""mesh""#).unwrap();
        assert_eq!(c, SetupComponent::Mesh);
    }

    // ── ComponentStatus ─────────────────────────────────────────────

    #[test]
    fn status_labels() {
        assert_eq!(ComponentStatus::Healthy.label(), "healthy");
        assert_eq!(ComponentStatus::Degraded.label(), "degraded");
        assert_eq!(ComponentStatus::Missing.label(), "missing");
        assert_eq!(ComponentStatus::Error.label(), "error");
    }

    #[test]
    fn status_display() {
        assert_eq!(format!("{}", ComponentStatus::Healthy), "healthy");
        assert_eq!(format!("{}", ComponentStatus::Error), "error");
    }

    #[test]
    fn status_is_problem() {
        assert!(!ComponentStatus::Healthy.is_problem());
        assert!(ComponentStatus::Degraded.is_problem());
        assert!(ComponentStatus::Missing.is_problem());
        assert!(ComponentStatus::Error.is_problem());
    }

    #[test]
    fn status_is_usable() {
        assert!(ComponentStatus::Healthy.is_usable());
        assert!(ComponentStatus::Degraded.is_usable());
        assert!(!ComponentStatus::Missing.is_usable());
        assert!(!ComponentStatus::Error.is_usable());
    }

    #[test]
    fn status_ord() {
        assert!(ComponentStatus::Error > ComponentStatus::Missing);
        assert!(ComponentStatus::Missing > ComponentStatus::Degraded);
        assert!(ComponentStatus::Degraded > ComponentStatus::Healthy);
    }

    // ── ComponentHealth ─────────────────────────────────────────────

    #[test]
    fn health_healthy_constructor() {
        let h = ComponentHealth::healthy(SetupComponent::Host);
        assert_eq!(h.status, ComponentStatus::Healthy);
        assert!(!h.has_problem());
        assert!(h.remediation.is_none());
    }

    #[test]
    fn health_degraded_constructor() {
        let h = ComponentHealth::degraded(SetupComponent::Mesh, "Slow peers", "Restart mesh");
        assert_eq!(h.status, ComponentStatus::Degraded);
        assert!(h.has_problem());
        assert_eq!(h.remediation.as_deref(), Some("Restart mesh"));
    }

    #[test]
    fn health_missing_constructor() {
        let h = ComponentHealth::missing(SetupComponent::Context, "Not found", "Run init");
        assert_eq!(h.status, ComponentStatus::Missing);
        assert!(h.has_problem());
    }

    #[test]
    fn health_error_constructor() {
        let h = ComponentHealth::error(SetupComponent::Host, "Crashed", "Restart");
        assert_eq!(h.status, ComponentStatus::Error);
        assert!(h.has_problem());
    }

    #[test]
    fn health_to_json() {
        let h = ComponentHealth::healthy(SetupComponent::Host);
        let json = h.to_json();
        assert_eq!(json["component"], "host");
        assert_eq!(json["status"], "healthy");
    }

    #[test]
    fn health_message_content() {
        let h = ComponentHealth::healthy(SetupComponent::Runtime);
        assert!(h.message.contains("Connector Runtime"));
    }

    #[test]
    fn health_degraded_message_custom() {
        let h = ComponentHealth::degraded(SetupComponent::Credentials, "Token expiring", "Refresh");
        assert_eq!(h.message, "Token expiring");
    }

    // ── OverallStatus ───────────────────────────────────────────────

    #[test]
    fn overall_status_labels() {
        assert_eq!(OverallStatus::Ready.label(), "ready");
        assert_eq!(OverallStatus::PartiallyReady.label(), "partially_ready");
        assert_eq!(OverallStatus::NotReady.label(), "not_ready");
    }

    #[test]
    fn overall_status_display() {
        assert_eq!(format!("{}", OverallStatus::Ready), "ready");
        assert_eq!(format!("{}", OverallStatus::NotReady), "not_ready");
    }

    // ── compute_overall_status ──────────────────────────────────────

    #[test]
    fn overall_ready_when_all_healthy() {
        let comps = vec![
            ComponentHealth::healthy(SetupComponent::Host),
            ComponentHealth::healthy(SetupComponent::Runtime),
            ComponentHealth::healthy(SetupComponent::Credentials),
        ];
        assert_eq!(compute_overall_status(&comps), OverallStatus::Ready);
    }

    #[test]
    fn overall_not_ready_when_empty() {
        assert_eq!(compute_overall_status(&[]), OverallStatus::NotReady);
    }

    #[test]
    fn overall_not_ready_when_host_missing() {
        let comps = vec![
            ComponentHealth::missing(SetupComponent::Host, "Missing", "Install"),
            ComponentHealth::healthy(SetupComponent::Runtime),
        ];
        assert_eq!(compute_overall_status(&comps), OverallStatus::NotReady);
    }

    #[test]
    fn overall_not_ready_when_error() {
        let comps = vec![
            ComponentHealth::healthy(SetupComponent::Host),
            ComponentHealth::error(SetupComponent::Connectivity, "Down", "Fix"),
        ];
        assert_eq!(compute_overall_status(&comps), OverallStatus::NotReady);
    }

    #[test]
    fn overall_partially_ready_when_degraded() {
        let comps = vec![
            ComponentHealth::healthy(SetupComponent::Host),
            ComponentHealth::healthy(SetupComponent::Runtime),
            ComponentHealth::degraded(SetupComponent::Mesh, "Slow", "Restart"),
        ];
        assert_eq!(
            compute_overall_status(&comps),
            OverallStatus::PartiallyReady
        );
    }

    #[test]
    fn overall_partially_ready_when_non_critical_missing() {
        let comps = vec![
            ComponentHealth::healthy(SetupComponent::Host),
            ComponentHealth::healthy(SetupComponent::Runtime),
            ComponentHealth::missing(SetupComponent::Mesh, "Not configured", "Configure"),
        ];
        assert_eq!(
            compute_overall_status(&comps),
            OverallStatus::PartiallyReady
        );
    }

    #[test]
    fn overall_not_ready_when_runtime_missing() {
        let comps = vec![
            ComponentHealth::healthy(SetupComponent::Host),
            ComponentHealth::missing(SetupComponent::Runtime, "Not installed", "Install"),
        ];
        assert_eq!(compute_overall_status(&comps), OverallStatus::NotReady);
    }

    // ── generate_recommendations ────────────────────────────────────

    #[test]
    fn recommendations_all_healthy() {
        let comps = vec![
            ComponentHealth::healthy(SetupComponent::Host),
            ComponentHealth::healthy(SetupComponent::Runtime),
        ];
        let recs = generate_recommendations(&comps);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].contains("healthy"));
    }

    #[test]
    fn recommendations_host_missing() {
        let comps = vec![ComponentHealth::missing(
            SetupComponent::Host,
            "Missing",
            "Install",
        )];
        let recs = generate_recommendations(&comps);
        assert!(recs.iter().any(|r| r.contains("host start")));
    }

    #[test]
    fn recommendations_credentials_missing() {
        let comps = vec![ComponentHealth::missing(
            SetupComponent::Credentials,
            "No creds",
            "Add",
        )];
        let recs = generate_recommendations(&comps);
        assert!(recs.iter().any(|r| r.contains("auth add")));
    }

    #[test]
    fn recommendations_context_missing() {
        let comps = vec![ComponentHealth::missing(
            SetupComponent::Context,
            "No context",
            "Init",
        )];
        let recs = generate_recommendations(&comps);
        assert!(recs.iter().any(|r| r.contains("setup init")));
    }

    #[test]
    fn recommendations_mesh_missing() {
        let comps = vec![ComponentHealth::missing(
            SetupComponent::Mesh,
            "No mesh",
            "Configure",
        )];
        let recs = generate_recommendations(&comps);
        assert!(recs.iter().any(|r| r.contains("mesh configure")));
    }

    #[test]
    fn recommendations_connectivity_error() {
        let comps = vec![ComponentHealth::error(
            SetupComponent::Connectivity,
            "Down",
            "Fix",
        )];
        let recs = generate_recommendations(&comps);
        assert!(recs.iter().any(|r| r.contains("network connectivity")));
    }

    #[test]
    fn recommendations_runtime_missing() {
        let comps = vec![ComponentHealth::missing(
            SetupComponent::Runtime,
            "Not installed",
            "Install",
        )];
        let recs = generate_recommendations(&comps);
        assert!(recs.iter().any(|r| r.contains("install")));
    }

    #[test]
    fn recommendations_host_error() {
        let comps = vec![ComponentHealth::error(
            SetupComponent::Host,
            "Crashed",
            "Restart",
        )];
        let recs = generate_recommendations(&comps);
        assert!(recs.iter().any(|r| r.contains("host restart")));
    }

    #[test]
    fn recommendations_credentials_degraded() {
        let comps = vec![ComponentHealth::degraded(
            SetupComponent::Credentials,
            "Expiring",
            "Refresh",
        )];
        let recs = generate_recommendations(&comps);
        assert!(recs.iter().any(|r| r.contains("auth status")));
    }

    #[test]
    fn recommendations_mesh_degraded() {
        let comps = vec![ComponentHealth::degraded(
            SetupComponent::Mesh,
            "Slow",
            "Restart",
        )];
        let recs = generate_recommendations(&comps);
        assert!(recs.iter().any(|r| r.contains("mesh status")));
    }

    #[test]
    fn recommendations_runtime_degraded() {
        let comps = vec![ComponentHealth::degraded(
            SetupComponent::Runtime,
            "Outdated",
            "Update",
        )];
        let recs = generate_recommendations(&comps);
        assert!(recs.iter().any(|r| r.contains("update")));
    }

    // ── SetupCheckArgs ──────────────────────────────────────────────

    #[test]
    fn check_args_default() {
        let args = SetupCheckArgs::new();
        assert!(args.component.is_none());
        assert!(!args.verbose);
    }

    #[test]
    fn check_args_builder() {
        let args = SetupCheckArgs::new()
            .with_component(SetupComponent::Host)
            .with_verbose(true);
        assert_eq!(args.component, Some(SetupComponent::Host));
        assert!(args.verbose);
    }

    #[test]
    fn check_args_default_trait() {
        let args = SetupCheckArgs::default();
        assert!(args.component.is_none());
    }

    // ── SetupRepairArgs ─────────────────────────────────────────────

    #[test]
    fn repair_args_default() {
        let args = SetupRepairArgs::new();
        assert!(args.component.is_none());
        assert!(!args.auto_fix);
        assert!(!args.dry_run);
    }

    #[test]
    fn repair_args_builder() {
        let args = SetupRepairArgs::new()
            .with_component(SetupComponent::Mesh)
            .with_auto_fix(true)
            .with_dry_run(true);
        assert_eq!(args.component, Some(SetupComponent::Mesh));
        assert!(args.auto_fix);
        assert!(args.dry_run);
    }

    #[test]
    fn repair_args_default_trait() {
        let args = SetupRepairArgs::default();
        assert!(!args.auto_fix);
    }

    // ── SetupInitArgs ───────────────────────────────────────────────

    #[test]
    fn init_args_basic() {
        let args = SetupInitArgs::new("my-project");
        assert_eq!(args.project_name, "my-project");
        assert!(args.template.is_none());
        assert!(!args.force);
    }

    #[test]
    fn init_args_builder() {
        let args = SetupInitArgs::new("proj")
            .with_template("mesh")
            .with_force(true);
        assert_eq!(args.template.as_deref(), Some("mesh"));
        assert!(args.force);
    }

    // ── SetupStatusArgs ─────────────────────────────────────────────

    #[test]
    fn status_args_default() {
        let args = SetupStatusArgs::new();
        assert!(args.component.is_none());
    }

    #[test]
    fn status_args_builder() {
        let args = SetupStatusArgs::new().with_component(SetupComponent::Connectivity);
        assert_eq!(args.component, Some(SetupComponent::Connectivity));
    }

    #[test]
    fn status_args_default_trait() {
        let args = SetupStatusArgs::default();
        assert!(args.component.is_none());
    }

    // ── SetupCheckResult ────────────────────────────────────────────

    #[test]
    fn check_result_all_healthy() {
        let comps = SetupComponent::all()
            .iter()
            .map(|c| ComponentHealth::healthy(*c))
            .collect();
        let result = SetupCheckResult::from_components(comps);
        assert!(result.all_healthy());
        assert_eq!(result.healthy_count(), 6);
        assert_eq!(result.problem_count(), 0);
        assert_eq!(result.total_count(), 6);
        assert_eq!(result.overall_status, OverallStatus::Ready);
    }

    #[test]
    fn check_result_some_degraded() {
        let comps = vec![
            ComponentHealth::healthy(SetupComponent::Host),
            ComponentHealth::degraded(SetupComponent::Mesh, "Slow", "Fix"),
            ComponentHealth::healthy(SetupComponent::Runtime),
        ];
        let result = SetupCheckResult::from_components(comps);
        assert!(!result.all_healthy());
        assert_eq!(result.healthy_count(), 2);
        assert_eq!(result.problem_count(), 1);
    }

    #[test]
    fn check_result_all_missing() {
        let comps = SetupComponent::all()
            .iter()
            .map(|c| ComponentHealth::missing(*c, "Missing", "Install"))
            .collect();
        let result = SetupCheckResult::from_components(comps);
        assert_eq!(result.healthy_count(), 0);
        assert_eq!(result.problem_count(), 6);
        assert_eq!(result.overall_status, OverallStatus::NotReady);
    }

    #[test]
    fn check_result_get_component() {
        let comps = vec![
            ComponentHealth::healthy(SetupComponent::Host),
            ComponentHealth::degraded(SetupComponent::Mesh, "Slow", "Fix"),
        ];
        let result = SetupCheckResult::from_components(comps);
        let host = result.get_component(SetupComponent::Host).unwrap();
        assert_eq!(host.status, ComponentStatus::Healthy);
        let mesh = result.get_component(SetupComponent::Mesh).unwrap();
        assert_eq!(mesh.status, ComponentStatus::Degraded);
        assert!(result.get_component(SetupComponent::Context).is_none());
    }

    #[test]
    fn check_result_to_json() {
        let comps = vec![ComponentHealth::healthy(SetupComponent::Host)];
        let result = SetupCheckResult::from_components(comps);
        let json = result.to_json();
        assert_eq!(json["overall_status"], "ready");
        assert!(json["components"].is_array());
    }

    #[test]
    fn check_result_recommendations_present() {
        let comps = vec![ComponentHealth::missing(
            SetupComponent::Context,
            "Missing",
            "Init",
        )];
        let result = SetupCheckResult::from_components(comps);
        assert!(!result.recommendations.is_empty());
    }

    // ── RepairActionType ────────────────────────────────────────────

    #[test]
    fn repair_action_type_labels() {
        assert_eq!(RepairActionType::Install.label(), "install");
        assert_eq!(RepairActionType::Reconfigure.label(), "reconfigure");
        assert_eq!(RepairActionType::Restart.label(), "restart");
        assert_eq!(RepairActionType::ClearState.label(), "clear_state");
        assert_eq!(RepairActionType::CreateResource.label(), "create_resource");
        assert_eq!(RepairActionType::Update.label(), "update");
    }

    #[test]
    fn repair_action_type_display() {
        assert_eq!(format!("{}", RepairActionType::Install), "install");
        assert_eq!(format!("{}", RepairActionType::Update), "update");
    }

    // ── RepairAction ────────────────────────────────────────────────

    #[test]
    fn repair_action_new() {
        let a = RepairAction::new(
            SetupComponent::Host,
            RepairActionType::Install,
            "Install host",
        );
        assert_eq!(a.component, SetupComponent::Host);
        assert_eq!(a.action_type, RepairActionType::Install);
        assert!(a.reversible);
        assert!(!a.applied);
    }

    #[test]
    fn repair_action_irreversible() {
        let a = RepairAction::new(
            SetupComponent::Connectivity,
            RepairActionType::Reconfigure,
            "Reset proxy",
        )
        .irreversible();
        assert!(!a.reversible);
        assert!(!a.is_auto_safe());
    }

    #[test]
    fn repair_action_mark_applied() {
        let mut a = RepairAction::new(SetupComponent::Host, RepairActionType::Restart, "Restart");
        assert!(!a.applied);
        a.mark_applied();
        assert!(a.applied);
    }

    #[test]
    fn repair_action_auto_safe() {
        let a = RepairAction::new(SetupComponent::Host, RepairActionType::Restart, "Restart");
        assert!(a.is_auto_safe()); // reversible → auto-safe

        let b = a.irreversible();
        assert!(!b.is_auto_safe());
    }

    // ── RepairResult ────────────────────────────────────────────────

    #[test]
    fn repair_result_empty() {
        let result = RepairResult::from_actions(Vec::new());
        assert!(result.nothing_to_do());
        assert!(!result.all_succeeded());
        assert_eq!(result.total_count(), 0);
    }

    #[test]
    fn repair_result_all_applied() {
        let mut a1 = RepairAction::new(SetupComponent::Host, RepairActionType::Restart, "R1");
        a1.mark_applied();
        let mut a2 = RepairAction::new(SetupComponent::Mesh, RepairActionType::Restart, "R2");
        a2.mark_applied();
        let result = RepairResult::from_actions(vec![a1, a2]);
        assert_eq!(result.success_count, 2);
        assert_eq!(result.skipped_count, 0);
        assert!(result.all_succeeded());
    }

    #[test]
    fn repair_result_some_skipped() {
        let mut a1 = RepairAction::new(SetupComponent::Host, RepairActionType::Restart, "R1");
        a1.mark_applied();
        let a2 = RepairAction::new(SetupComponent::Mesh, RepairActionType::Install, "I1");
        let result = RepairResult::from_actions(vec![a1, a2]);
        assert_eq!(result.success_count, 1);
        assert_eq!(result.skipped_count, 1);
        assert!(!result.all_succeeded());
    }

    #[test]
    fn repair_result_with_failures() {
        let mut a1 = RepairAction::new(SetupComponent::Host, RepairActionType::Restart, "R1");
        a1.mark_applied();
        let a2 = RepairAction::new(SetupComponent::Mesh, RepairActionType::Install, "I1");
        let result = RepairResult::with_failures(vec![a1, a2], 1);
        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 1);
        assert_eq!(result.skipped_count, 0);
    }

    #[test]
    fn repair_result_to_json() {
        let result = RepairResult::from_actions(Vec::new());
        let json = result.to_json();
        assert!(json["actions"].is_array());
        assert_eq!(json["success_count"], 0);
    }

    // ── plan_repair ─────────────────────────────────────────────────

    #[test]
    fn plan_repair_host_missing() {
        let h = ComponentHealth::missing(SetupComponent::Host, "Missing", "Install");
        let actions = plan_repair(&h);
        assert!(!actions.is_empty());
        assert_eq!(actions[0].action_type, RepairActionType::Install);
    }

    #[test]
    fn plan_repair_host_error() {
        let h = ComponentHealth::error(SetupComponent::Host, "Crashed", "Restart");
        let actions = plan_repair(&h);
        assert_eq!(actions[0].action_type, RepairActionType::Restart);
    }

    #[test]
    fn plan_repair_host_degraded() {
        let h = ComponentHealth::degraded(SetupComponent::Host, "Slow", "Reconfigure");
        let actions = plan_repair(&h);
        assert_eq!(actions[0].action_type, RepairActionType::Reconfigure);
    }

    #[test]
    fn plan_repair_credentials_missing() {
        let h = ComponentHealth::missing(SetupComponent::Credentials, "No creds", "Init");
        let actions = plan_repair(&h);
        assert_eq!(actions[0].action_type, RepairActionType::CreateResource);
    }

    #[test]
    fn plan_repair_credentials_degraded() {
        let h = ComponentHealth::degraded(SetupComponent::Credentials, "Expiring", "Refresh");
        let actions = plan_repair(&h);
        assert_eq!(actions[0].action_type, RepairActionType::Reconfigure);
    }

    #[test]
    fn plan_repair_context_missing_creates_two_actions() {
        let h = ComponentHealth::missing(SetupComponent::Context, "Not found", "Create");
        let actions = plan_repair(&h);
        assert_eq!(actions.len(), 2);
        assert!(
            actions
                .iter()
                .all(|a| a.action_type == RepairActionType::CreateResource)
        );
    }

    #[test]
    fn plan_repair_context_error() {
        let h = ComponentHealth::error(SetupComponent::Context, "Corrupted", "Clear");
        let actions = plan_repair(&h);
        assert_eq!(actions[0].action_type, RepairActionType::ClearState);
    }

    #[test]
    fn plan_repair_mesh_missing() {
        let h = ComponentHealth::missing(SetupComponent::Mesh, "Not configured", "Init");
        let actions = plan_repair(&h);
        assert_eq!(actions[0].action_type, RepairActionType::Install);
    }

    #[test]
    fn plan_repair_mesh_degraded() {
        let h = ComponentHealth::degraded(SetupComponent::Mesh, "Slow", "Restart");
        let actions = plan_repair(&h);
        assert_eq!(actions[0].action_type, RepairActionType::Restart);
    }

    #[test]
    fn plan_repair_connectivity_error_irreversible() {
        let h = ComponentHealth::error(SetupComponent::Connectivity, "Down", "Fix");
        let actions = plan_repair(&h);
        assert_eq!(actions[0].action_type, RepairActionType::Reconfigure);
        assert!(!actions[0].reversible);
    }

    #[test]
    fn plan_repair_connectivity_degraded() {
        let h = ComponentHealth::degraded(SetupComponent::Connectivity, "Slow DNS", "Clear");
        let actions = plan_repair(&h);
        assert_eq!(actions[0].action_type, RepairActionType::ClearState);
    }

    #[test]
    fn plan_repair_runtime_missing() {
        let h = ComponentHealth::missing(SetupComponent::Runtime, "Not installed", "Install");
        let actions = plan_repair(&h);
        assert_eq!(actions[0].action_type, RepairActionType::Install);
    }

    #[test]
    fn plan_repair_runtime_degraded() {
        let h = ComponentHealth::degraded(SetupComponent::Runtime, "Outdated", "Update");
        let actions = plan_repair(&h);
        assert_eq!(actions[0].action_type, RepairActionType::Update);
    }

    #[test]
    fn plan_repair_healthy_no_actions() {
        let h = ComponentHealth::healthy(SetupComponent::Host);
        let actions = plan_repair(&h);
        assert!(actions.is_empty());
    }

    // ── repair_setup ────────────────────────────────────────────────

    #[test]
    fn repair_dry_run_nothing_applied() {
        let comps = vec![
            ComponentHealth::missing(SetupComponent::Host, "Missing", "Install"),
            ComponentHealth::degraded(SetupComponent::Mesh, "Slow", "Fix"),
        ];
        let check_result = SetupCheckResult::from_components(comps);
        let args = SetupRepairArgs::new().with_dry_run(true);
        let result = repair_setup(&args, &check_result);
        assert!(result.actions.iter().all(|a| !a.applied));
        assert_eq!(result.success_count, 0);
    }

    #[test]
    fn repair_auto_fix_only_safe_actions() {
        let comps = vec![
            ComponentHealth::error(SetupComponent::Connectivity, "Down", "Fix"),
            ComponentHealth::degraded(SetupComponent::Mesh, "Slow", "Restart"),
        ];
        let check_result = SetupCheckResult::from_components(comps);
        let args = SetupRepairArgs::new().with_auto_fix(true);
        let result = repair_setup(&args, &check_result);
        // Connectivity repair is irreversible, so not auto-safe.
        let connectivity_actions: Vec<_> = result
            .actions
            .iter()
            .filter(|a| a.component == SetupComponent::Connectivity)
            .collect();
        assert!(connectivity_actions.iter().all(|a| !a.applied));
        // Mesh repair is reversible, so auto-applied.
        let mesh_actions: Vec<_> = result
            .actions
            .iter()
            .filter(|a| a.component == SetupComponent::Mesh)
            .collect();
        assert!(mesh_actions.iter().all(|a| a.applied));
    }

    #[test]
    fn repair_all_applied_without_auto_fix() {
        let comps = vec![ComponentHealth::degraded(
            SetupComponent::Mesh,
            "Slow",
            "Restart",
        )];
        let check_result = SetupCheckResult::from_components(comps);
        let args = SetupRepairArgs::new(); // no auto_fix, no dry_run
        let result = repair_setup(&args, &check_result);
        assert!(result.actions.iter().all(|a| a.applied));
    }

    #[test]
    fn repair_filter_by_component() {
        let comps = vec![
            ComponentHealth::missing(SetupComponent::Host, "Missing", "Install"),
            ComponentHealth::degraded(SetupComponent::Mesh, "Slow", "Fix"),
        ];
        let check_result = SetupCheckResult::from_components(comps);
        let args = SetupRepairArgs::new().with_component(SetupComponent::Mesh);
        let result = repair_setup(&args, &check_result);
        assert!(
            result
                .actions
                .iter()
                .all(|a| a.component == SetupComponent::Mesh)
        );
    }

    #[test]
    fn repair_nothing_to_do_when_healthy() {
        let comps = vec![ComponentHealth::healthy(SetupComponent::Host)];
        let check_result = SetupCheckResult::from_components(comps);
        let args = SetupRepairArgs::new();
        let result = repair_setup(&args, &check_result);
        assert!(result.nothing_to_do());
    }

    #[test]
    fn repair_partial_failure_tracking() {
        let mut a1 = RepairAction::new(SetupComponent::Host, RepairActionType::Restart, "R1");
        a1.mark_applied();
        let a2 = RepairAction::new(SetupComponent::Mesh, RepairActionType::Install, "I1");
        let result = RepairResult::with_failures(vec![a1, a2], 1);
        assert_eq!(result.failure_count, 1);
        assert!(!result.all_succeeded());
    }

    // ── init_setup ──────────────────────────────────────────────────

    #[test]
    fn init_basic_project() {
        let args = SetupInitArgs::new("my-project");
        let result = init_setup(&args).unwrap();
        assert_eq!(result.project_path, PathBuf::from("my-project"));
        assert!(!result.config_files_created.is_empty());
        assert!(!result.next_steps.is_empty());
    }

    #[test]
    fn init_empty_name_error() {
        let args = SetupInitArgs::new("");
        let err = init_setup(&args).unwrap_err();
        assert!(matches!(err, InitError::InvalidName(_)));
    }

    #[test]
    fn init_long_name_error() {
        let name = "a".repeat(200);
        let args = SetupInitArgs::new(name);
        let err = init_setup(&args).unwrap_err();
        assert!(matches!(err, InitError::InvalidName(_)));
    }

    #[test]
    fn init_invalid_chars_error() {
        let args = SetupInitArgs::new("my project/bad");
        let err = init_setup(&args).unwrap_err();
        assert!(matches!(err, InitError::InvalidName(_)));
    }

    #[test]
    fn init_default_template() {
        let args = SetupInitArgs::new("test-proj");
        let result = init_setup(&args).unwrap();
        assert!(result.config_files_created.contains(&"fcp.toml".to_owned()));
        assert!(
            result
                .config_files_created
                .contains(&".fcp/credentials.json".to_owned())
        );
    }

    #[test]
    fn init_mesh_template() {
        let args = SetupInitArgs::new("mesh-proj").with_template("mesh");
        let result = init_setup(&args).unwrap();
        assert!(
            result
                .config_files_created
                .contains(&".fcp/mesh.toml".to_owned())
        );
        assert!(
            result
                .config_files_created
                .contains(&".fcp/peers.json".to_owned())
        );
    }

    #[test]
    fn init_minimal_template() {
        let args = SetupInitArgs::new("min-proj").with_template("minimal");
        let result = init_setup(&args).unwrap();
        // Minimal does not include credentials.json.
        assert!(
            !result
                .config_files_created
                .contains(&".fcp/credentials.json".to_owned())
        );
        assert!(result.config_files_created.contains(&"fcp.toml".to_owned()));
    }

    #[test]
    fn init_full_template() {
        let args = SetupInitArgs::new("full-proj").with_template("full");
        let result = init_setup(&args).unwrap();
        assert!(
            result
                .config_files_created
                .contains(&".fcp/policies.toml".to_owned())
        );
        assert!(
            result
                .config_files_created
                .contains(&".fcp/zones.json".to_owned())
        );
    }

    #[test]
    fn init_mesh_template_includes_mesh_next_step() {
        let args = SetupInitArgs::new("mesh-proj").with_template("mesh");
        let result = init_setup(&args).unwrap();
        assert!(
            result
                .next_steps
                .iter()
                .any(|s| s.contains("mesh configure"))
        );
    }

    #[test]
    fn init_next_steps_include_cd() {
        let args = SetupInitArgs::new("my-proj");
        let result = init_setup(&args).unwrap();
        assert!(result.next_steps.iter().any(|s| s.contains("cd my-proj")));
    }

    #[test]
    fn init_next_steps_include_auth() {
        let args = SetupInitArgs::new("my-proj");
        let result = init_setup(&args).unwrap();
        assert!(result.next_steps.iter().any(|s| s.contains("auth add")));
    }

    #[test]
    fn init_next_steps_include_setup_check() {
        let args = SetupInitArgs::new("my-proj");
        let result = init_setup(&args).unwrap();
        assert!(result.next_steps.iter().any(|s| s.contains("setup check")));
    }

    #[test]
    fn init_result_file_count() {
        let args = SetupInitArgs::new("test-proj");
        let result = init_setup(&args).unwrap();
        assert_eq!(result.file_count(), result.config_files_created.len());
        assert!(result.file_count() >= 2); // At least fcp.toml + config.json
    }

    #[test]
    fn init_result_to_json() {
        let args = SetupInitArgs::new("test-proj");
        let result = init_setup(&args).unwrap();
        let json = result.to_json();
        assert!(json["config_files_created"].is_array());
        assert!(json["next_steps"].is_array());
    }

    #[test]
    fn init_valid_name_with_dots() {
        let args = SetupInitArgs::new("my.project.v2");
        assert!(init_setup(&args).is_ok());
    }

    #[test]
    fn init_valid_name_with_underscore() {
        let args = SetupInitArgs::new("my_project");
        assert!(init_setup(&args).is_ok());
    }

    #[test]
    fn init_valid_name_with_hyphen() {
        let args = SetupInitArgs::new("my-project");
        assert!(init_setup(&args).is_ok());
    }

    // ── InitError ───────────────────────────────────────────────────

    #[test]
    fn init_error_display_invalid_name() {
        let e = InitError::InvalidName("too long".to_owned());
        let s = format!("{e}");
        assert!(s.contains("invalid project name"));
        assert!(s.contains("too long"));
    }

    #[test]
    fn init_error_display_already_exists() {
        let e = InitError::AlreadyExists(PathBuf::from("/tmp/existing"));
        let s = format!("{e}");
        assert!(s.contains("already exists"));
    }

    #[test]
    fn init_error_display_unknown_template() {
        let e = InitError::UnknownTemplate("fancy".to_owned());
        let s = format!("{e}");
        assert!(s.contains("unknown template"));
    }

    #[test]
    fn init_error_display_io() {
        let e = InitError::IoError("permission denied".to_owned());
        let s = format!("{e}");
        assert!(s.contains("I/O error"));
    }

    // ── check_setup ─────────────────────────────────────────────────

    #[test]
    fn check_setup_all_components() {
        let args = SetupCheckArgs::new();
        let result = check_setup(&args);
        assert_eq!(result.total_count(), 6);
    }

    #[test]
    fn check_setup_single_component() {
        let args = SetupCheckArgs::new().with_component(SetupComponent::Host);
        let result = check_setup(&args);
        assert_eq!(result.total_count(), 1);
        assert_eq!(result.components[0].component, SetupComponent::Host);
    }

    #[test]
    fn check_setup_verbose_flag() {
        let args = SetupCheckArgs::new().with_verbose(true);
        let result = check_setup(&args);
        // Verbose just adds detail; check still works.
        assert!(result.total_count() > 0);
    }

    // ── check_setup_with_health ─────────────────────────────────────

    #[test]
    fn check_with_health_map_overrides() {
        let mut map = BTreeMap::new();
        map.insert(
            SetupComponent::Host,
            ComponentHealth::error(SetupComponent::Host, "Dead", "Restart"),
        );
        let result = check_setup_with_health(&map);
        let host = result.get_component(SetupComponent::Host).unwrap();
        assert_eq!(host.status, ComponentStatus::Error);
        // Other components default to healthy.
        let mesh = result.get_component(SetupComponent::Mesh).unwrap();
        assert_eq!(mesh.status, ComponentStatus::Healthy);
    }

    #[test]
    fn check_with_health_map_empty() {
        let map = BTreeMap::new();
        let result = check_setup_with_health(&map);
        assert!(result.all_healthy());
    }

    // ── setup_status ────────────────────────────────────────────────

    #[test]
    fn setup_status_all() {
        let args = SetupStatusArgs::new();
        let result = setup_status(&args);
        assert_eq!(result.total_count(), 6);
    }

    #[test]
    fn setup_status_filtered() {
        let args = SetupStatusArgs::new().with_component(SetupComponent::Mesh);
        let result = setup_status(&args);
        assert_eq!(result.total_count(), 1);
    }

    // ── format_check_toon ───────────────────────────────────────────

    #[test]
    fn format_check_toon_all_healthy() {
        let comps = SetupComponent::all()
            .iter()
            .map(|c| ComponentHealth::healthy(*c))
            .collect();
        let result = SetupCheckResult::from_components(comps);
        let lines = format_check_toon(&result);
        assert!(lines[0].contains("ready"));
        assert!(lines[0].contains("6/6"));
        assert!(lines.iter().any(|l| l.contains("[OK]")));
    }

    #[test]
    fn format_check_toon_with_degraded() {
        let comps = vec![
            ComponentHealth::healthy(SetupComponent::Host),
            ComponentHealth::degraded(SetupComponent::Mesh, "Slow peers", "Restart mesh"),
        ];
        let result = SetupCheckResult::from_components(comps);
        let lines = format_check_toon(&result);
        assert!(lines.iter().any(|l| l.contains("[!!]")));
        assert!(lines.iter().any(|l| l.contains("Remedy:")));
    }

    #[test]
    fn format_check_toon_with_missing() {
        let comps = vec![ComponentHealth::missing(
            SetupComponent::Context,
            "Not found",
            "Init",
        )];
        let result = SetupCheckResult::from_components(comps);
        let lines = format_check_toon(&result);
        assert!(lines.iter().any(|l| l.contains("[--]")));
    }

    #[test]
    fn format_check_toon_with_error() {
        let comps = vec![ComponentHealth::error(
            SetupComponent::Host,
            "Crashed",
            "Restart",
        )];
        let result = SetupCheckResult::from_components(comps);
        let lines = format_check_toon(&result);
        assert!(lines.iter().any(|l| l.contains("[XX]")));
    }

    #[test]
    fn format_check_toon_recommendations() {
        let comps = vec![ComponentHealth::missing(
            SetupComponent::Context,
            "Missing",
            "Init",
        )];
        let result = SetupCheckResult::from_components(comps);
        let lines = format_check_toon(&result);
        assert!(lines.iter().any(|l| l.contains("Recommendations:")));
    }

    #[test]
    fn format_check_toon_returns_vec_string() {
        let comps = vec![ComponentHealth::healthy(SetupComponent::Host)];
        let result = SetupCheckResult::from_components(comps);
        let lines: Vec<String> = format_check_toon(&result);
        assert!(!lines.is_empty());
    }

    // ── format_repair_toon ──────────────────────────────────────────

    #[test]
    fn format_repair_toon_nothing_to_do() {
        let result = RepairResult::from_actions(Vec::new());
        let lines = format_repair_toon(&result);
        assert!(lines[0].contains("nothing to do"));
    }

    #[test]
    fn format_repair_toon_with_actions() {
        let mut a1 = RepairAction::new(SetupComponent::Host, RepairActionType::Restart, "Restart");
        a1.mark_applied();
        let a2 = RepairAction::new(SetupComponent::Mesh, RepairActionType::Install, "Install");
        let result = RepairResult::from_actions(vec![a1, a2]);
        let lines = format_repair_toon(&result);
        assert!(lines[0].contains("2 actions"));
        assert!(lines.iter().any(|l| l.contains("[DONE]")));
        assert!(lines.iter().any(|l| l.contains("[SKIP]")));
    }

    #[test]
    fn format_repair_toon_irreversible_marker() {
        let a = RepairAction::new(
            SetupComponent::Connectivity,
            RepairActionType::Reconfigure,
            "Reset proxy",
        )
        .irreversible();
        let result = RepairResult::from_actions(vec![a]);
        let lines = format_repair_toon(&result);
        assert!(lines.iter().any(|l| l.contains("(irreversible)")));
    }

    // ── format_init_toon ────────────────────────────────────────────

    #[test]
    fn format_init_toon_basic() {
        let args = SetupInitArgs::new("my-proj");
        let result = init_setup(&args).unwrap();
        let lines = format_init_toon(&result);
        assert!(lines[0].contains("my-proj"));
        assert!(lines.iter().any(|l| l.contains("Files created")));
        assert!(lines.iter().any(|l| l.contains("Next steps")));
    }

    #[test]
    fn format_init_toon_lists_files() {
        let args = SetupInitArgs::new("proj");
        let result = init_setup(&args).unwrap();
        let lines = format_init_toon(&result);
        assert!(lines.iter().any(|l| l.contains("fcp.toml")));
    }

    #[test]
    fn format_init_toon_numbered_steps() {
        let args = SetupInitArgs::new("proj");
        let result = init_setup(&args).unwrap();
        let lines = format_init_toon(&result);
        assert!(lines.iter().any(|l| l.starts_with("  1.")));
        assert!(lines.iter().any(|l| l.starts_with("  2.")));
    }

    // ── format_status_toon ──────────────────────────────────────────

    #[test]
    fn format_status_toon_ready() {
        let comps = SetupComponent::all()
            .iter()
            .map(|c| ComponentHealth::healthy(*c))
            .collect();
        let result = SetupCheckResult::from_components(comps);
        let lines = format_status_toon(&result);
        assert!(lines[0].contains("READY"));
        assert!(lines.iter().any(|l| l.starts_with("  +")));
    }

    #[test]
    fn format_status_toon_partial() {
        let comps = vec![
            ComponentHealth::healthy(SetupComponent::Host),
            ComponentHealth::healthy(SetupComponent::Runtime),
            ComponentHealth::degraded(SetupComponent::Mesh, "Slow", "Fix"),
        ];
        let result = SetupCheckResult::from_components(comps);
        let lines = format_status_toon(&result);
        assert!(lines[0].contains("PARTIAL"));
        assert!(lines.iter().any(|l| l.starts_with("  ~")));
    }

    #[test]
    fn format_status_toon_not_ready() {
        let comps = vec![ComponentHealth::error(SetupComponent::Host, "Down", "Fix")];
        let result = SetupCheckResult::from_components(comps);
        let lines = format_status_toon(&result);
        assert!(lines[0].contains("NOT READY"));
        assert!(lines.iter().any(|l| l.starts_with("  !")));
    }

    #[test]
    fn format_status_toon_missing_marker() {
        let comps = vec![ComponentHealth::missing(
            SetupComponent::Context,
            "Missing",
            "Init",
        )];
        let result = SetupCheckResult::from_components(comps);
        let lines = format_status_toon(&result);
        assert!(lines.iter().any(|l| l.starts_with("  -")));
    }

    // ── format_init_error_toon ──────────────────────────────────────

    #[test]
    fn format_init_error_invalid_name() {
        let e = InitError::InvalidName("bad chars".to_owned());
        let lines = format_init_error_toon(&e);
        assert!(lines[0].contains("Init failed"));
        assert!(lines.iter().any(|l| l.contains("alphanumeric")));
    }

    #[test]
    fn format_init_error_already_exists() {
        let e = InitError::AlreadyExists(PathBuf::from("/tmp/existing"));
        let lines = format_init_error_toon(&e);
        assert!(lines.iter().any(|l| l.contains("--force")));
    }

    #[test]
    fn format_init_error_unknown_template() {
        let e = InitError::UnknownTemplate("fancy".to_owned());
        let lines = format_init_error_toon(&e);
        assert!(lines.iter().any(|l| l.contains("Available templates")));
    }

    #[test]
    fn format_init_error_io() {
        let e = InitError::IoError("disk full".to_owned());
        let lines = format_init_error_toon(&e);
        assert!(lines.iter().any(|l| l.contains("permissions")));
    }

    // ── repair_order ────────────────────────────────────────────────

    #[test]
    fn repair_order_starts_with_host() {
        let order = repair_order();
        assert_eq!(order[0], SetupComponent::Host);
    }

    #[test]
    fn repair_order_connectivity_before_mesh() {
        let order = repair_order();
        let conn_idx = order
            .iter()
            .position(|c| *c == SetupComponent::Connectivity)
            .unwrap();
        let mesh_idx = order
            .iter()
            .position(|c| *c == SetupComponent::Mesh)
            .unwrap();
        assert!(conn_idx < mesh_idx);
    }

    #[test]
    fn repair_order_host_before_runtime() {
        let order = repair_order();
        let host_idx = order
            .iter()
            .position(|c| *c == SetupComponent::Host)
            .unwrap();
        let rt_idx = order
            .iter()
            .position(|c| *c == SetupComponent::Runtime)
            .unwrap();
        assert!(host_idx < rt_idx);
    }

    #[test]
    fn repair_order_contains_all() {
        let order = repair_order();
        assert_eq!(order.len(), 6);
        for c in SetupComponent::all() {
            assert!(order.contains(c));
        }
    }

    // ── is_known_template ───────────────────────────────────────────

    #[test]
    fn known_templates() {
        assert!(is_known_template("default"));
        assert!(is_known_template("minimal"));
        assert!(is_known_template("mesh"));
        assert!(is_known_template("full"));
    }

    #[test]
    fn unknown_templates() {
        assert!(!is_known_template("fancy"));
        assert!(!is_known_template(""));
        assert!(!is_known_template("DEFAULT")); // case-sensitive
    }

    // ── generate_config_files ───────────────────────────────────────

    #[test]
    fn config_files_default_template() {
        let files = generate_config_files("default");
        assert!(files.contains(&"fcp.toml".to_owned()));
        assert!(files.contains(&".fcp/config.json".to_owned()));
        assert!(files.contains(&".fcp/credentials.json".to_owned()));
    }

    #[test]
    fn config_files_mesh_template() {
        let files = generate_config_files("mesh");
        assert!(files.contains(&".fcp/mesh.toml".to_owned()));
        assert!(files.contains(&".fcp/peers.json".to_owned()));
    }

    #[test]
    fn config_files_minimal_template() {
        let files = generate_config_files("minimal");
        assert_eq!(files.len(), 2); // Only fcp.toml + config.json
    }

    #[test]
    fn config_files_full_template() {
        let files = generate_config_files("full");
        assert!(files.contains(&".fcp/policies.toml".to_owned()));
        assert!(files.contains(&".fcp/zones.json".to_owned()));
    }

    #[test]
    fn config_files_unknown_template() {
        let files = generate_config_files("unknown");
        assert_eq!(files.len(), 2); // Fallback to base files
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn repair_empty_check_result() {
        let check_result = SetupCheckResult::from_components(Vec::new());
        let args = SetupRepairArgs::new();
        let result = repair_setup(&args, &check_result);
        assert!(result.nothing_to_do());
    }

    #[test]
    fn repair_dry_run_with_auto_fix() {
        // dry_run takes precedence over auto_fix.
        let comps = vec![ComponentHealth::degraded(
            SetupComponent::Mesh,
            "Slow",
            "Restart",
        )];
        let check_result = SetupCheckResult::from_components(comps);
        let args = SetupRepairArgs::new()
            .with_auto_fix(true)
            .with_dry_run(true);
        let result = repair_setup(&args, &check_result);
        assert!(result.actions.iter().all(|a| !a.applied));
    }

    #[test]
    fn check_result_single_error_component() {
        let comps = vec![ComponentHealth::error(
            SetupComponent::Host,
            "Segfault",
            "Reinstall",
        )];
        let result = SetupCheckResult::from_components(comps);
        assert_eq!(result.overall_status, OverallStatus::NotReady);
        assert_eq!(result.problem_count(), 1);
    }

    #[test]
    fn health_map_multiple_failures() {
        let mut map = BTreeMap::new();
        map.insert(
            SetupComponent::Host,
            ComponentHealth::error(SetupComponent::Host, "Dead", "Restart"),
        );
        map.insert(
            SetupComponent::Connectivity,
            ComponentHealth::missing(SetupComponent::Connectivity, "No net", "Fix"),
        );
        let result = check_setup_with_health(&map);
        assert_eq!(result.overall_status, OverallStatus::NotReady);
        assert_eq!(result.problem_count(), 2);
    }

    #[test]
    fn component_serialize_roundtrip() {
        for c in SetupComponent::all() {
            let json = serde_json::to_string(c).unwrap();
            let parsed: SetupComponent = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, parsed);
        }
    }

    #[test]
    fn format_check_toon_empty_components() {
        let result = SetupCheckResult::from_components(Vec::new());
        let lines = format_check_toon(&result);
        assert!(lines[0].contains("not_ready"));
        assert!(lines[0].contains("0/0"));
    }

    #[test]
    fn format_status_toon_single_component() {
        let comps = vec![ComponentHealth::healthy(SetupComponent::Host)];
        let result = SetupCheckResult::from_components(comps);
        let lines = format_status_toon(&result);
        assert_eq!(lines.len(), 2); // status line + one component
    }

    #[test]
    fn repair_action_description_preserved() {
        let a = RepairAction::new(
            SetupComponent::Host,
            RepairActionType::Install,
            "Install the FCP host binary from registry",
        );
        assert_eq!(a.description, "Install the FCP host binary from registry");
    }

    #[test]
    fn init_result_add_multiple_files() {
        let mut result = InitResult::new(PathBuf::from("proj"));
        result.add_config_file("a.toml");
        result.add_config_file("b.json");
        result.add_config_file("c.yaml");
        assert_eq!(result.file_count(), 3);
    }

    #[test]
    fn init_result_add_multiple_steps() {
        let mut result = InitResult::new(PathBuf::from("proj"));
        result.add_next_step("Step 1");
        result.add_next_step("Step 2");
        assert_eq!(result.next_steps.len(), 2);
    }
}
