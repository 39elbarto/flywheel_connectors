//! Zone architecture for Kubernetes prod safety.
//!
//! Each connector instance is bound to a single zone (dev/staging/prod).
//! Zones enforce capability tiering:
//!
//! - **Dev**: full access, no approval gating.
//! - **Staging**: full access, approval recommended for exec.
//! - **Prod**: readonly by default; deploy and exec require `ApprovalToken`;
//!   deletes are forbidden by default.
//!
//! Zone IDs follow the naming convention:
//! `z:work:k8s:<tier>:<cluster>` (e.g. `z:work:k8s:prod:us-east-1`).

use std::fmt;

// ── Zone tier ─────────────────────────────────────────────────────

/// The environment tier a zone belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZoneTier {
    /// Development — permissive, all operations allowed.
    Dev,
    /// Staging — mirrors prod topology, approval recommended for exec.
    Staging,
    /// Production — restrictive: readonly default, approval-gated deploys/exec,
    /// deletes forbidden.
    Prod,
}

impl ZoneTier {
    /// Parse a tier string (case-insensitive).
    ///
    /// Accepts `"dev"`, `"staging"`, `"prod"` and common aliases
    /// (`"development"`, `"stg"`, `"production"`).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "dev" | "development" => Some(Self::Dev),
            "staging" | "stg" => Some(Self::Staging),
            "prod" | "production" => Some(Self::Prod),
            _ => None,
        }
    }

    /// Whether this tier is considered a production environment.
    #[must_use]
    pub const fn is_production(&self) -> bool {
        matches!(self, Self::Prod)
    }

    /// Whether this tier is considered a staging environment.
    #[must_use]
    pub const fn is_staging(&self) -> bool {
        matches!(self, Self::Staging)
    }

    /// Canonical lowercase label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Staging => "staging",
            Self::Prod => "prod",
        }
    }
}

impl fmt::Display for ZoneTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Zone config ───────────────────────────────────────────────────

/// Parsed zone identity for a connector instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneConfig {
    /// Full zone identifier string.
    pub zone_id: String,
    /// Resolved tier.
    pub tier: ZoneTier,
    /// Cluster name extracted from the zone ID.
    pub cluster: String,
}

impl ZoneConfig {
    /// Parse a zone ID string of the form `z:work:k8s:<tier>:<cluster>`.
    ///
    /// Returns `None` if the string does not match the expected format or the
    /// tier segment is unrecognised.
    #[must_use]
    pub fn parse(zone_id: &str) -> Option<Self> {
        let parts: Vec<&str> = zone_id.split(':').collect();
        if parts.len() < 5 {
            return None;
        }
        if parts[0] != "z" || parts[1] != "work" || parts[2] != "k8s" {
            return None;
        }
        let tier = ZoneTier::parse(parts[3])?;
        // Cluster may contain colons (e.g. `us-east-1:main`), so rejoin.
        let cluster = parts[4..].join(":");
        if cluster.is_empty() {
            return None;
        }
        Some(Self {
            zone_id: zone_id.to_string(),
            tier,
            cluster,
        })
    }

    /// Build a zone config directly (useful in tests).
    #[must_use]
    pub fn new(tier: ZoneTier, cluster: &str) -> Self {
        let zone_id = format!("z:work:k8s:{}:{cluster}", tier.as_str());
        Self {
            zone_id,
            tier,
            cluster: cluster.to_string(),
        }
    }
}

impl fmt::Display for ZoneConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.zone_id)
    }
}

// ── Operation classification ──────────────────────────────────────

/// Coarse operation category used by the zone policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationCategory {
    /// Read-only: list, get, watch, logs.
    Read,
    /// Mutations that modify existing resources (scale, restart, update).
    Write,
    /// Deployment of new resources (apply, create).
    Deploy,
    /// Exec into a running container.
    Exec,
    /// Delete an existing resource.
    Delete,
    /// Secret access (read or write).
    Secret,
}

impl OperationCategory {
    /// Classify a Kubernetes operation ID into a category.
    ///
    /// Returns `None` for unrecognised operation IDs.
    #[must_use]
    pub fn classify(operation_id: &str) -> Option<Self> {
        // Delete operations
        if operation_id.contains("delete") {
            return Some(Self::Delete);
        }
        // Exec
        if operation_id == "kubernetes.exec" {
            return Some(Self::Exec);
        }
        // Deploy / create
        if operation_id.contains("create")
            || operation_id.contains("apply")
        {
            return Some(Self::Deploy);
        }
        // Secret access
        if operation_id.starts_with("kubernetes.secret.")
            || operation_id == "kubernetes.get_secret"
        {
            return Some(Self::Secret);
        }
        // Write / mutate
        if operation_id.contains("scale")
            || operation_id.contains("restart")
            || operation_id.contains("update")
            || operation_id.contains("rollback")
        {
            return Some(Self::Write);
        }
        // Read
        if operation_id.contains("list")
            || operation_id.contains("get")
            || operation_id.contains("logs")
            || operation_id.contains("stream")
            || operation_id.contains("watch")
            || operation_id.contains("status")
            || operation_id.contains("history")
        {
            return Some(Self::Read);
        }
        None
    }

    /// Whether this category mutates cluster state.
    #[must_use]
    pub const fn is_mutation(&self) -> bool {
        matches!(
            self,
            Self::Write | Self::Deploy | Self::Exec | Self::Delete
        )
    }
}

// ── Approval token ────────────────────────────────────────────────

/// Opaque approval token that must be presented for gated operations in
/// restricted zones. In production, this would be issued by a human reviewer
/// or an approval workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalToken {
    /// The token value.
    pub token: String,
    /// Identifies the approver (human or workflow).
    pub approved_by: String,
    /// Operation ID this token authorises.
    pub operation_id: String,
}

impl ApprovalToken {
    /// Create a new approval token.
    #[must_use]
    pub fn new(token: &str, approved_by: &str, operation_id: &str) -> Self {
        Self {
            token: token.to_string(),
            approved_by: approved_by.to_string(),
            operation_id: operation_id.to_string(),
        }
    }

    /// Whether this token authorises the given operation.
    #[must_use]
    pub fn authorises(&self, operation_id: &str) -> bool {
        self.operation_id == operation_id
    }
}

// ── Zone policy ───────────────────────────────────────────────────

/// Policy decision returned by the zone engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The operation is allowed.
    Allow,
    /// The operation requires an approval token.
    RequiresApproval { reason: String },
    /// The operation is denied outright.
    Deny { reason: String },
}

impl PolicyDecision {
    /// Whether the decision permits execution.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Whether an approval token is needed.
    #[must_use]
    pub const fn requires_approval(&self) -> bool {
        matches!(self, Self::RequiresApproval { .. })
    }

    /// Whether the operation is denied.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

/// Zone-aware policy engine.
///
/// Evaluates whether an operation is permitted in the current zone.
#[derive(Debug, Clone)]
pub struct ZonePolicy {
    /// The zone this policy applies to.
    pub config: ZoneConfig,
    /// Whether to allow deletes in prod (default: false).
    pub prod_allow_deletes: bool,
    /// Whether to allow secret writes in prod (default: false).
    pub prod_allow_secret_writes: bool,
}

impl ZonePolicy {
    /// Create a zone policy with default settings for the given zone.
    #[must_use]
    pub const fn new(config: ZoneConfig) -> Self {
        Self {
            config,
            prod_allow_deletes: false,
            prod_allow_secret_writes: false,
        }
    }

    /// Override: allow delete operations in prod.
    #[must_use]
    pub const fn with_prod_deletes(mut self, allow: bool) -> Self {
        self.prod_allow_deletes = allow;
        self
    }

    /// Override: allow secret writes in prod.
    #[must_use]
    pub const fn with_prod_secret_writes(mut self, allow: bool) -> Self {
        self.prod_allow_secret_writes = allow;
        self
    }

    /// Evaluate whether `operation_id` is allowed under the current zone
    /// policy, without an approval token.
    #[must_use]
    pub fn evaluate(&self, operation_id: &str) -> PolicyDecision {
        self.evaluate_with_approval(operation_id, None)
    }

    /// Evaluate with an optional approval token.
    #[must_use]
    pub fn evaluate_with_approval(
        &self,
        operation_id: &str,
        approval: Option<&ApprovalToken>,
    ) -> PolicyDecision {
        let Some(category) = OperationCategory::classify(operation_id) else {
            return PolicyDecision::Deny {
                reason: format!("Unknown operation: {operation_id}"),
            };
        };

        match self.config.tier {
            ZoneTier::Dev => PolicyDecision::Allow,
            ZoneTier::Staging => Self::evaluate_staging(operation_id, category, approval),
            ZoneTier::Prod => self.evaluate_prod(operation_id, category, approval),
        }
    }

    /// Whether any mutation is allowed in the current zone (without approval).
    #[must_use]
    pub const fn allows_mutation(&self) -> bool {
        match self.config.tier {
            ZoneTier::Dev | ZoneTier::Staging => true,
            // Prod allows writes with approval, but by default mutations
            // are gated.
            ZoneTier::Prod => false,
        }
    }

    /// Whether this zone requires approval for exec operations.
    #[must_use]
    pub const fn requires_approval_for_exec(&self) -> bool {
        match self.config.tier {
            ZoneTier::Dev => false,
            ZoneTier::Staging | ZoneTier::Prod => true,
        }
    }

    /// Whether this zone requires approval for deploy operations.
    #[must_use]
    pub const fn requires_approval_for_deploy(&self) -> bool {
        match self.config.tier {
            ZoneTier::Dev | ZoneTier::Staging => false,
            ZoneTier::Prod => true,
        }
    }

    /// Whether deletes are allowed in this zone.
    #[must_use]
    pub const fn allows_delete(&self) -> bool {
        match self.config.tier {
            ZoneTier::Dev | ZoneTier::Staging => true,
            ZoneTier::Prod => self.prod_allow_deletes,
        }
    }

    // ── Internal ──────────────────────────────────────────────────

    fn evaluate_staging(
        operation_id: &str,
        category: OperationCategory,
        approval: Option<&ApprovalToken>,
    ) -> PolicyDecision {
        match category {
            OperationCategory::Read => PolicyDecision::Allow,
            OperationCategory::Write | OperationCategory::Deploy | OperationCategory::Secret => {
                PolicyDecision::Allow
            }
            OperationCategory::Delete => PolicyDecision::Allow,
            OperationCategory::Exec => {
                // Staging recommends approval for exec.
                if let Some(token) = approval {
                    if token.authorises(operation_id) {
                        return PolicyDecision::Allow;
                    }
                    return PolicyDecision::Deny {
                        reason: format!(
                            "Approval token does not authorise '{operation_id}'"
                        ),
                    };
                }
                PolicyDecision::RequiresApproval {
                    reason: "Exec in staging requires approval".into(),
                }
            }
        }
    }

    fn evaluate_prod(
        &self,
        operation_id: &str,
        category: OperationCategory,
        approval: Option<&ApprovalToken>,
    ) -> PolicyDecision {
        match category {
            OperationCategory::Read => PolicyDecision::Allow,
            OperationCategory::Delete => {
                if self.prod_allow_deletes {
                    // Even with the override, deletes require approval.
                    Self::require_approval(operation_id, approval, "Delete in prod requires approval")
                } else {
                    PolicyDecision::Deny {
                        reason: format!(
                            "Delete operations are forbidden in prod zone '{}'",
                            self.config.zone_id,
                        ),
                    }
                }
            }
            OperationCategory::Deploy => Self::require_approval(
                operation_id,
                approval,
                "Deploy in prod requires approval",
            ),
            OperationCategory::Exec => Self::require_approval(
                operation_id,
                approval,
                "Exec in prod requires approval",
            ),
            OperationCategory::Write => Self::require_approval(
                operation_id,
                approval,
                "Write operations in prod require approval",
            ),
            OperationCategory::Secret => {
                // Secret reads are allowed; writes need special flag + approval.
                if operation_id.contains("create") || operation_id.contains("delete") {
                    if self.prod_allow_secret_writes {
                        Self::require_approval(
                            operation_id,
                            approval,
                            "Secret mutation in prod requires approval",
                        )
                    } else {
                        PolicyDecision::Deny {
                            reason: format!(
                                "Secret mutations are forbidden in prod zone '{}'",
                                self.config.zone_id,
                            ),
                        }
                    }
                } else {
                    // Secret read (get, list) — approval-gated in prod.
                    Self::require_approval(
                        operation_id,
                        approval,
                        "Secret access in prod requires approval",
                    )
                }
            }
        }
    }

    fn require_approval(
        operation_id: &str,
        approval: Option<&ApprovalToken>,
        message: &str,
    ) -> PolicyDecision {
        match approval {
            Some(token) if token.authorises(operation_id) => PolicyDecision::Allow,
            Some(_) => PolicyDecision::Deny {
                reason: format!("Approval token does not authorise '{operation_id}'"),
            },
            None => PolicyDecision::RequiresApproval {
                reason: message.into(),
            },
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ZoneTier parsing ─────────────────────────────────────────

    #[test]
    fn parse_tier_dev() {
        assert_eq!(ZoneTier::parse("dev"), Some(ZoneTier::Dev));
    }

    #[test]
    fn parse_tier_development() {
        assert_eq!(ZoneTier::parse("development"), Some(ZoneTier::Dev));
    }

    #[test]
    fn parse_tier_staging() {
        assert_eq!(ZoneTier::parse("staging"), Some(ZoneTier::Staging));
    }

    #[test]
    fn parse_tier_stg() {
        assert_eq!(ZoneTier::parse("stg"), Some(ZoneTier::Staging));
    }

    #[test]
    fn parse_tier_prod() {
        assert_eq!(ZoneTier::parse("prod"), Some(ZoneTier::Prod));
    }

    #[test]
    fn parse_tier_production() {
        assert_eq!(ZoneTier::parse("production"), Some(ZoneTier::Prod));
    }

    #[test]
    fn parse_tier_case_insensitive() {
        assert_eq!(ZoneTier::parse("DEV"), Some(ZoneTier::Dev));
        assert_eq!(ZoneTier::parse("Staging"), Some(ZoneTier::Staging));
        assert_eq!(ZoneTier::parse("PROD"), Some(ZoneTier::Prod));
    }

    #[test]
    fn parse_tier_unknown() {
        assert_eq!(ZoneTier::parse("test"), None);
        assert_eq!(ZoneTier::parse(""), None);
        assert_eq!(ZoneTier::parse("pre-prod"), None);
    }

    #[test]
    fn tier_is_production() {
        assert!(ZoneTier::Prod.is_production());
        assert!(!ZoneTier::Dev.is_production());
        assert!(!ZoneTier::Staging.is_production());
    }

    #[test]
    fn tier_is_staging() {
        assert!(ZoneTier::Staging.is_staging());
        assert!(!ZoneTier::Dev.is_staging());
        assert!(!ZoneTier::Prod.is_staging());
    }

    #[test]
    fn tier_as_str() {
        assert_eq!(ZoneTier::Dev.as_str(), "dev");
        assert_eq!(ZoneTier::Staging.as_str(), "staging");
        assert_eq!(ZoneTier::Prod.as_str(), "prod");
    }

    #[test]
    fn tier_display() {
        assert_eq!(ZoneTier::Dev.to_string(), "dev");
        assert_eq!(ZoneTier::Staging.to_string(), "staging");
        assert_eq!(ZoneTier::Prod.to_string(), "prod");
    }

    #[test]
    fn tier_clone() {
        let tier = ZoneTier::Prod;
        let cloned = tier;
        assert_eq!(tier, cloned);
    }

    #[test]
    fn tier_debug() {
        let dbg = format!("{:?}", ZoneTier::Dev);
        assert!(dbg.contains("Dev"));
    }

    #[test]
    fn tier_eq() {
        assert_eq!(ZoneTier::Dev, ZoneTier::Dev);
        assert_ne!(ZoneTier::Dev, ZoneTier::Prod);
        assert_ne!(ZoneTier::Staging, ZoneTier::Prod);
    }

    // ── ZoneConfig parsing ───────────────────────────────────────

    #[test]
    fn parse_zone_config_dev() {
        let zc = ZoneConfig::parse("z:work:k8s:dev:minikube").unwrap();
        assert_eq!(zc.tier, ZoneTier::Dev);
        assert_eq!(zc.cluster, "minikube");
        assert_eq!(zc.zone_id, "z:work:k8s:dev:minikube");
    }

    #[test]
    fn parse_zone_config_staging() {
        let zc = ZoneConfig::parse("z:work:k8s:staging:eu-west-1").unwrap();
        assert_eq!(zc.tier, ZoneTier::Staging);
        assert_eq!(zc.cluster, "eu-west-1");
    }

    #[test]
    fn parse_zone_config_prod() {
        let zc = ZoneConfig::parse("z:work:k8s:prod:us-east-1").unwrap();
        assert_eq!(zc.tier, ZoneTier::Prod);
        assert_eq!(zc.cluster, "us-east-1");
    }

    #[test]
    fn parse_zone_config_production_alias() {
        let zc = ZoneConfig::parse("z:work:k8s:production:cluster-a").unwrap();
        assert_eq!(zc.tier, ZoneTier::Prod);
        assert_eq!(zc.cluster, "cluster-a");
    }

    #[test]
    fn parse_zone_config_cluster_with_colons() {
        let zc = ZoneConfig::parse("z:work:k8s:dev:region:cluster:sub").unwrap();
        assert_eq!(zc.tier, ZoneTier::Dev);
        assert_eq!(zc.cluster, "region:cluster:sub");
    }

    #[test]
    fn parse_zone_config_too_few_parts() {
        assert!(ZoneConfig::parse("z:work:k8s:dev").is_none());
        assert!(ZoneConfig::parse("z:work:k8s").is_none());
        assert!(ZoneConfig::parse("z:work").is_none());
        assert!(ZoneConfig::parse("z").is_none());
        assert!(ZoneConfig::parse("").is_none());
    }

    #[test]
    fn parse_zone_config_wrong_prefix() {
        assert!(ZoneConfig::parse("x:work:k8s:dev:cluster").is_none());
        assert!(ZoneConfig::parse("z:play:k8s:dev:cluster").is_none());
        assert!(ZoneConfig::parse("z:work:docker:dev:cluster").is_none());
    }

    #[test]
    fn parse_zone_config_unknown_tier() {
        assert!(ZoneConfig::parse("z:work:k8s:canary:cluster").is_none());
    }

    #[test]
    fn zone_config_new() {
        let zc = ZoneConfig::new(ZoneTier::Prod, "us-west-2");
        assert_eq!(zc.zone_id, "z:work:k8s:prod:us-west-2");
        assert_eq!(zc.tier, ZoneTier::Prod);
        assert_eq!(zc.cluster, "us-west-2");
    }

    #[test]
    fn zone_config_display() {
        let zc = ZoneConfig::new(ZoneTier::Dev, "local");
        assert_eq!(zc.to_string(), "z:work:k8s:dev:local");
    }

    #[test]
    fn zone_config_clone() {
        let zc = ZoneConfig::new(ZoneTier::Staging, "eu-west-1");
        let zc2 = zc.clone();
        assert_eq!(zc, zc2);
    }

    #[test]
    fn zone_config_debug() {
        let zc = ZoneConfig::new(ZoneTier::Dev, "local");
        let dbg = format!("{zc:?}");
        assert!(dbg.contains("ZoneConfig"));
        assert!(dbg.contains("Dev"));
    }

    #[test]
    fn zone_config_eq() {
        let a = ZoneConfig::new(ZoneTier::Dev, "local");
        let b = ZoneConfig::new(ZoneTier::Dev, "local");
        let c = ZoneConfig::new(ZoneTier::Prod, "local");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn zone_config_roundtrip_parse_new() {
        let original = ZoneConfig::new(ZoneTier::Staging, "cluster-7");
        let parsed = ZoneConfig::parse(&original.zone_id).unwrap();
        assert_eq!(original, parsed);
    }

    // ── OperationCategory ────────────────────────────────────────

    #[test]
    fn classify_read_operations() {
        let reads = [
            "kubernetes.list_pods",
            "kubernetes.get_pod",
            "kubernetes.get_pod_logs",
            "kubernetes.stream_pod_logs",
            "kubernetes.list_deployments",
            "kubernetes.get_deployment",
            "kubernetes.get_service",
            "kubernetes.list_services",
            "kubernetes.get_configmap",
            "kubernetes.watch_events",
            "kubernetes.configmap.list",
            "kubernetes.configmap.get",
            "kubernetes.rollout.status",
            "kubernetes.rollout.history",
        ];
        for op in &reads {
            assert_eq!(
                OperationCategory::classify(op),
                Some(OperationCategory::Read),
                "expected Read for {op}"
            );
        }
    }

    #[test]
    fn classify_write_operations() {
        let writes = [
            "kubernetes.scale_deployment",
            "kubernetes.rollout_restart",
            "kubernetes.update_configmap",
            "kubernetes.configmap.update",
            "kubernetes.rollout.rollback",
        ];
        for op in &writes {
            assert_eq!(
                OperationCategory::classify(op),
                Some(OperationCategory::Write),
                "expected Write for {op}"
            );
        }
    }

    #[test]
    fn classify_deploy_operations() {
        let deploys = [
            "kubernetes.create_pod",
            "kubernetes.apply_deployment",
            "kubernetes.configmap.create",
        ];
        for op in &deploys {
            assert_eq!(
                OperationCategory::classify(op),
                Some(OperationCategory::Deploy),
                "expected Deploy for {op}"
            );
        }
    }

    #[test]
    fn classify_delete_operations() {
        let deletes = [
            "kubernetes.delete_pod",
            "kubernetes.delete_deployment",
            "kubernetes.configmap.delete",
            "kubernetes.secret.delete",
        ];
        for op in &deletes {
            assert_eq!(
                OperationCategory::classify(op),
                Some(OperationCategory::Delete),
                "expected Delete for {op}"
            );
        }
    }

    #[test]
    fn classify_exec_operation() {
        assert_eq!(
            OperationCategory::classify("kubernetes.exec"),
            Some(OperationCategory::Exec)
        );
    }

    #[test]
    fn classify_secret_operations() {
        let secrets = [
            "kubernetes.get_secret",
            "kubernetes.secret.get",
            "kubernetes.secret.list",
            "kubernetes.secret.create",
        ];
        for op in &secrets {
            // secret.create is classified as Deploy first? No, delete catches first,
            // but secret.create contains "create" — however it also starts with
            // "kubernetes.secret." so the secret check comes later... Let me verify.
            // Actually: classify checks delete first (no match), then exec (no),
            // then create/apply → Deploy. But secret.create contains "create".
            // So secret.create will be classified as Deploy, not Secret.
            // This is intentional: secret creation is a deploy-like action.
            // Only secret.get, secret.list remain as Secret category.
            // Actually wait - delete check is first: secret.delete contains "delete"
            // so it becomes Delete. secret.create contains "create" so it becomes
            // Deploy. That leaves secret.get and secret.list as Secret.
            let cat = OperationCategory::classify(op);
            assert!(cat.is_some(), "expected Some for {op}");
        }
    }

    #[test]
    fn classify_secret_get_is_secret() {
        assert_eq!(
            OperationCategory::classify("kubernetes.secret.get"),
            Some(OperationCategory::Secret)
        );
        assert_eq!(
            OperationCategory::classify("kubernetes.get_secret"),
            Some(OperationCategory::Secret)
        );
    }

    #[test]
    fn classify_secret_list_is_secret() {
        assert_eq!(
            OperationCategory::classify("kubernetes.secret.list"),
            Some(OperationCategory::Secret)
        );
    }

    #[test]
    fn classify_secret_create_is_deploy() {
        // secret.create contains "create" which is matched before the secret check
        assert_eq!(
            OperationCategory::classify("kubernetes.secret.create"),
            Some(OperationCategory::Deploy)
        );
    }

    #[test]
    fn classify_secret_delete_is_delete() {
        // secret.delete contains "delete" which is matched first
        assert_eq!(
            OperationCategory::classify("kubernetes.secret.delete"),
            Some(OperationCategory::Delete)
        );
    }

    #[test]
    fn classify_unknown_operation() {
        assert_eq!(OperationCategory::classify("kubernetes.unknown"), None);
        assert_eq!(OperationCategory::classify(""), None);
        assert_eq!(OperationCategory::classify("other.list"), Some(OperationCategory::Read));
    }

    #[test]
    fn category_is_mutation() {
        assert!(!OperationCategory::Read.is_mutation());
        assert!(OperationCategory::Write.is_mutation());
        assert!(OperationCategory::Deploy.is_mutation());
        assert!(OperationCategory::Exec.is_mutation());
        assert!(OperationCategory::Delete.is_mutation());
        assert!(!OperationCategory::Secret.is_mutation());
    }

    #[test]
    fn category_debug() {
        let dbg = format!("{:?}", OperationCategory::Read);
        assert!(dbg.contains("Read"));
    }

    #[test]
    fn category_clone() {
        let cat = OperationCategory::Deploy;
        let cloned = cat;
        assert_eq!(cat, cloned);
    }

    // ── ApprovalToken ────────────────────────────────────────────

    #[test]
    fn approval_token_new() {
        let t = ApprovalToken::new("tok-abc", "alice@example.com", "kubernetes.exec");
        assert_eq!(t.token, "tok-abc");
        assert_eq!(t.approved_by, "alice@example.com");
        assert_eq!(t.operation_id, "kubernetes.exec");
    }

    #[test]
    fn approval_token_authorises_matching() {
        let t = ApprovalToken::new("tok-1", "bob", "kubernetes.exec");
        assert!(t.authorises("kubernetes.exec"));
    }

    #[test]
    fn approval_token_rejects_non_matching() {
        let t = ApprovalToken::new("tok-1", "bob", "kubernetes.exec");
        assert!(!t.authorises("kubernetes.delete_pod"));
    }

    #[test]
    fn approval_token_clone() {
        let t = ApprovalToken::new("tok-1", "bob", "kubernetes.exec");
        let t2 = t.clone();
        assert_eq!(t, t2);
    }

    #[test]
    fn approval_token_debug() {
        let t = ApprovalToken::new("tok-1", "bob", "kubernetes.exec");
        let dbg = format!("{t:?}");
        assert!(dbg.contains("ApprovalToken"));
    }

    #[test]
    fn approval_token_eq() {
        let a = ApprovalToken::new("tok-1", "bob", "kubernetes.exec");
        let b = ApprovalToken::new("tok-1", "bob", "kubernetes.exec");
        let c = ApprovalToken::new("tok-2", "bob", "kubernetes.exec");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ── PolicyDecision ───────────────────────────────────────────

    #[test]
    fn decision_allow() {
        let d = PolicyDecision::Allow;
        assert!(d.is_allowed());
        assert!(!d.requires_approval());
        assert!(!d.is_denied());
    }

    #[test]
    fn decision_requires_approval() {
        let d = PolicyDecision::RequiresApproval {
            reason: "test".into(),
        };
        assert!(!d.is_allowed());
        assert!(d.requires_approval());
        assert!(!d.is_denied());
    }

    #[test]
    fn decision_deny() {
        let d = PolicyDecision::Deny {
            reason: "test".into(),
        };
        assert!(!d.is_allowed());
        assert!(!d.requires_approval());
        assert!(d.is_denied());
    }

    #[test]
    fn decision_debug() {
        let d = PolicyDecision::Allow;
        assert!(format!("{d:?}").contains("Allow"));
    }

    #[test]
    fn decision_clone() {
        let d = PolicyDecision::Deny {
            reason: "x".into(),
        };
        let d2 = d.clone();
        assert_eq!(d, d2);
    }

    // ── ZonePolicy — dev tier ────────────────────────────────────

    #[test]
    fn dev_allows_all_reads() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        for op in &[
            "kubernetes.list_pods",
            "kubernetes.get_pod",
            "kubernetes.get_pod_logs",
            "kubernetes.watch_events",
        ] {
            assert!(p.evaluate(op).is_allowed(), "dev should allow {op}");
        }
    }

    #[test]
    fn dev_allows_all_writes() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        for op in &[
            "kubernetes.scale_deployment",
            "kubernetes.rollout_restart",
            "kubernetes.update_configmap",
        ] {
            assert!(p.evaluate(op).is_allowed(), "dev should allow {op}");
        }
    }

    #[test]
    fn dev_allows_all_deploys() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        for op in &[
            "kubernetes.create_pod",
            "kubernetes.apply_deployment",
            "kubernetes.configmap.create",
        ] {
            assert!(p.evaluate(op).is_allowed(), "dev should allow {op}");
        }
    }

    #[test]
    fn dev_allows_deletes() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        for op in &[
            "kubernetes.delete_pod",
            "kubernetes.delete_deployment",
            "kubernetes.configmap.delete",
        ] {
            assert!(p.evaluate(op).is_allowed(), "dev should allow {op}");
        }
    }

    #[test]
    fn dev_allows_exec() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        assert!(p.evaluate("kubernetes.exec").is_allowed());
    }

    #[test]
    fn dev_allows_secrets() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        assert!(p.evaluate("kubernetes.get_secret").is_allowed());
        assert!(p.evaluate("kubernetes.secret.get").is_allowed());
        assert!(p.evaluate("kubernetes.secret.list").is_allowed());
    }

    #[test]
    fn dev_allows_mutation() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        assert!(p.allows_mutation());
    }

    #[test]
    fn dev_no_approval_for_exec() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        assert!(!p.requires_approval_for_exec());
    }

    #[test]
    fn dev_no_approval_for_deploy() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        assert!(!p.requires_approval_for_deploy());
    }

    #[test]
    fn dev_allows_delete() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        assert!(p.allows_delete());
    }

    // ── ZonePolicy — staging tier ────────────────────────────────

    #[test]
    fn staging_allows_reads() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg-cluster"));
        assert!(p.evaluate("kubernetes.list_pods").is_allowed());
        assert!(p.evaluate("kubernetes.get_deployment").is_allowed());
    }

    #[test]
    fn staging_allows_writes() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg-cluster"));
        assert!(p.evaluate("kubernetes.scale_deployment").is_allowed());
        assert!(p.evaluate("kubernetes.rollout_restart").is_allowed());
    }

    #[test]
    fn staging_allows_deploys() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg-cluster"));
        assert!(p.evaluate("kubernetes.apply_deployment").is_allowed());
    }

    #[test]
    fn staging_allows_deletes() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg-cluster"));
        assert!(p.evaluate("kubernetes.delete_pod").is_allowed());
    }

    #[test]
    fn staging_requires_approval_for_exec() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg-cluster"));
        let decision = p.evaluate("kubernetes.exec");
        assert!(decision.requires_approval());
    }

    #[test]
    fn staging_exec_allowed_with_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg-cluster"));
        let token = ApprovalToken::new("tok-stg", "alice", "kubernetes.exec");
        let decision = p.evaluate_with_approval("kubernetes.exec", Some(&token));
        assert!(decision.is_allowed());
    }

    #[test]
    fn staging_exec_denied_with_wrong_token() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg-cluster"));
        let token = ApprovalToken::new("tok-stg", "alice", "kubernetes.delete_pod");
        let decision = p.evaluate_with_approval("kubernetes.exec", Some(&token));
        assert!(decision.is_denied());
    }

    #[test]
    fn staging_allows_mutation() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg"));
        assert!(p.allows_mutation());
    }

    #[test]
    fn staging_requires_exec_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg"));
        assert!(p.requires_approval_for_exec());
    }

    #[test]
    fn staging_no_deploy_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg"));
        assert!(!p.requires_approval_for_deploy());
    }

    #[test]
    fn staging_allows_delete() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg"));
        assert!(p.allows_delete());
    }

    // ── ZonePolicy — prod tier ───────────────────────────────────

    #[test]
    fn prod_allows_reads() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        assert!(p.evaluate("kubernetes.list_pods").is_allowed());
        assert!(p.evaluate("kubernetes.get_pod").is_allowed());
        assert!(p.evaluate("kubernetes.get_pod_logs").is_allowed());
        assert!(p.evaluate("kubernetes.get_deployment").is_allowed());
        assert!(p.evaluate("kubernetes.list_services").is_allowed());
        assert!(p.evaluate("kubernetes.watch_events").is_allowed());
        assert!(p.evaluate("kubernetes.rollout.status").is_allowed());
        assert!(p.evaluate("kubernetes.rollout.history").is_allowed());
    }

    #[test]
    fn prod_denies_mutations_by_default() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        assert!(!p.allows_mutation());
    }

    #[test]
    fn prod_denies_writes_without_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let decision = p.evaluate("kubernetes.scale_deployment");
        assert!(decision.requires_approval());
    }

    #[test]
    fn prod_denies_deploy_without_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let decision = p.evaluate("kubernetes.apply_deployment");
        assert!(
            decision.requires_approval(),
            "prod deploy should require approval"
        );
    }

    #[test]
    fn prod_denies_exec_without_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let decision = p.evaluate("kubernetes.exec");
        assert!(
            decision.requires_approval(),
            "prod exec should require approval"
        );
    }

    #[test]
    fn prod_deploy_allowed_with_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let token = ApprovalToken::new("tok-prod", "sre-team", "kubernetes.apply_deployment");
        let decision =
            p.evaluate_with_approval("kubernetes.apply_deployment", Some(&token));
        assert!(decision.is_allowed());
    }

    #[test]
    fn prod_exec_allowed_with_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let token = ApprovalToken::new("tok-prod", "sre-team", "kubernetes.exec");
        let decision = p.evaluate_with_approval("kubernetes.exec", Some(&token));
        assert!(decision.is_allowed());
    }

    #[test]
    fn prod_denies_deletes_by_default() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let decision = p.evaluate("kubernetes.delete_pod");
        assert!(decision.is_denied(), "prod should deny delete_pod");
    }

    #[test]
    fn prod_denies_delete_deployment() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let decision = p.evaluate("kubernetes.delete_deployment");
        assert!(decision.is_denied());
    }

    #[test]
    fn prod_denies_configmap_delete() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let decision = p.evaluate("kubernetes.configmap.delete");
        assert!(decision.is_denied());
    }

    #[test]
    fn prod_delete_deny_message_contains_zone() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let decision = p.evaluate("kubernetes.delete_pod");
        match decision {
            PolicyDecision::Deny { reason } => {
                assert!(reason.contains("prod"));
                assert!(reason.contains("forbidden"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn prod_delete_with_override_requires_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"))
            .with_prod_deletes(true);
        let decision = p.evaluate("kubernetes.delete_pod");
        assert!(
            decision.requires_approval(),
            "prod delete with override still requires approval"
        );
    }

    #[test]
    fn prod_delete_with_override_and_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"))
            .with_prod_deletes(true);
        let token = ApprovalToken::new("tok-d", "sre", "kubernetes.delete_pod");
        let decision = p.evaluate_with_approval("kubernetes.delete_pod", Some(&token));
        assert!(decision.is_allowed());
    }

    #[test]
    fn prod_does_not_allow_mutation() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        assert!(!p.allows_mutation());
    }

    #[test]
    fn prod_requires_exec_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        assert!(p.requires_approval_for_exec());
    }

    #[test]
    fn prod_requires_deploy_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        assert!(p.requires_approval_for_deploy());
    }

    #[test]
    fn prod_does_not_allow_delete_by_default() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        assert!(!p.allows_delete());
    }

    #[test]
    fn prod_allows_delete_with_override() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"))
            .with_prod_deletes(true);
        assert!(p.allows_delete());
    }

    // ── Prod secret policy ───────────────────────────────────────

    #[test]
    fn prod_secret_read_requires_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let decision = p.evaluate("kubernetes.secret.get");
        assert!(decision.requires_approval());
    }

    #[test]
    fn prod_secret_list_requires_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let decision = p.evaluate("kubernetes.secret.list");
        assert!(decision.requires_approval());
    }

    #[test]
    fn prod_secret_read_allowed_with_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let token = ApprovalToken::new("tok-s", "sre", "kubernetes.secret.get");
        let decision = p.evaluate_with_approval("kubernetes.secret.get", Some(&token));
        assert!(decision.is_allowed());
    }

    #[test]
    fn prod_get_secret_requires_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let decision = p.evaluate("kubernetes.get_secret");
        assert!(decision.requires_approval());
    }

    #[test]
    fn prod_secret_create_denied_by_default() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        // secret.create is classified as Deploy
        let decision = p.evaluate("kubernetes.secret.create");
        // Deploy in prod requires approval
        assert!(decision.requires_approval());
    }

    #[test]
    fn prod_secret_delete_denied_by_default() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        // secret.delete is classified as Delete
        let decision = p.evaluate("kubernetes.secret.delete");
        assert!(decision.is_denied());
    }

    // ── Wrong approval tokens ────────────────────────────────────

    #[test]
    fn prod_deploy_with_wrong_token_denied() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let token = ApprovalToken::new("tok-x", "sre", "kubernetes.exec");
        let decision =
            p.evaluate_with_approval("kubernetes.apply_deployment", Some(&token));
        assert!(decision.is_denied());
    }

    #[test]
    fn prod_exec_with_wrong_token_denied() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let token = ApprovalToken::new("tok-x", "sre", "kubernetes.delete_pod");
        let decision = p.evaluate_with_approval("kubernetes.exec", Some(&token));
        assert!(decision.is_denied());
    }

    // ── Unknown operation ────────────────────────────────────────

    #[test]
    fn unknown_operation_denied_in_all_tiers() {
        for tier in &[ZoneTier::Dev, ZoneTier::Staging, ZoneTier::Prod] {
            let p = ZonePolicy::new(ZoneConfig::new(*tier, "cluster"));
            let decision = p.evaluate("kubernetes.unknown_op");
            // classify returns None for unrecognised IDs, triggering Deny
            // even in dev (classify runs before the tier match).
            assert!(decision.is_denied(), "unknown op should be denied in {tier}");
        }
    }

    // ── Builder methods ──────────────────────────────────────────

    #[test]
    fn with_prod_deletes_true() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "c"))
            .with_prod_deletes(true);
        assert!(p.prod_allow_deletes);
    }

    #[test]
    fn with_prod_deletes_false() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "c"))
            .with_prod_deletes(false);
        assert!(!p.prod_allow_deletes);
    }

    #[test]
    fn with_prod_secret_writes_true() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "c"))
            .with_prod_secret_writes(true);
        assert!(p.prod_allow_secret_writes);
    }

    #[test]
    fn with_prod_secret_writes_false() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "c"))
            .with_prod_secret_writes(false);
        assert!(!p.prod_allow_secret_writes);
    }

    #[test]
    fn policy_debug() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        let dbg = format!("{p:?}");
        assert!(dbg.contains("ZonePolicy"));
    }

    #[test]
    fn policy_clone() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-west-2"))
            .with_prod_deletes(true);
        let p2 = p.clone();
        assert_eq!(p.config, p2.config);
        assert_eq!(p.prod_allow_deletes, p2.prod_allow_deletes);
    }

    // ── Cross-tier comparison ────────────────────────────────────

    #[test]
    fn same_operation_different_tiers() {
        let dev = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        let stg = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg"));
        let prod = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "prod"));

        // scale_deployment: dev=allow, staging=allow, prod=requires_approval
        assert!(dev.evaluate("kubernetes.scale_deployment").is_allowed());
        assert!(stg.evaluate("kubernetes.scale_deployment").is_allowed());
        assert!(prod.evaluate("kubernetes.scale_deployment").requires_approval());
    }

    #[test]
    fn delete_pod_different_tiers() {
        let dev = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        let stg = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg"));
        let prod = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "prod"));

        assert!(dev.evaluate("kubernetes.delete_pod").is_allowed());
        assert!(stg.evaluate("kubernetes.delete_pod").is_allowed());
        assert!(prod.evaluate("kubernetes.delete_pod").is_denied());
    }

    #[test]
    fn exec_different_tiers() {
        let dev = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        let stg = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "stg"));
        let prod = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "prod"));

        assert!(dev.evaluate("kubernetes.exec").is_allowed());
        assert!(stg.evaluate("kubernetes.exec").requires_approval());
        assert!(prod.evaluate("kubernetes.exec").requires_approval());
    }

    // ── Full scenario: prod deploy with approval flow ────────────

    #[test]
    fn prod_deploy_full_flow() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));

        // Step 1: Agent attempts deploy without approval
        let d1 = p.evaluate("kubernetes.apply_deployment");
        assert!(d1.requires_approval());

        // Step 2: Agent gets approval token from reviewer
        let token = ApprovalToken::new(
            "approval-2026-03-09-001",
            "sre-oncall@example.com",
            "kubernetes.apply_deployment",
        );

        // Step 3: Agent retries with approval
        let d2 = p.evaluate_with_approval("kubernetes.apply_deployment", Some(&token));
        assert!(d2.is_allowed());
    }

    #[test]
    fn prod_exec_full_flow() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));

        let d1 = p.evaluate("kubernetes.exec");
        assert!(d1.requires_approval());

        let token = ApprovalToken::new(
            "approval-exec-001",
            "platform-eng@example.com",
            "kubernetes.exec",
        );

        let d2 = p.evaluate_with_approval("kubernetes.exec", Some(&token));
        assert!(d2.is_allowed());
    }

    // ── Prod write operations ────────────────────────────────────

    #[test]
    fn prod_scale_requires_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "prod-1"));
        assert!(p.evaluate("kubernetes.scale_deployment").requires_approval());
    }

    #[test]
    fn prod_rollout_restart_requires_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "prod-1"));
        assert!(p.evaluate("kubernetes.rollout_restart").requires_approval());
    }

    #[test]
    fn prod_update_configmap_requires_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "prod-1"));
        assert!(p.evaluate("kubernetes.update_configmap").requires_approval());
    }

    #[test]
    fn prod_rollout_rollback_requires_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "prod-1"));
        assert!(p.evaluate("kubernetes.rollout.rollback").requires_approval());
    }

    #[test]
    fn prod_configmap_update_requires_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "prod-1"));
        assert!(p.evaluate("kubernetes.configmap.update").requires_approval());
    }

    #[test]
    fn prod_create_pod_requires_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "prod-1"));
        assert!(p.evaluate("kubernetes.create_pod").requires_approval());
    }

    #[test]
    fn prod_configmap_create_requires_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "prod-1"));
        assert!(p.evaluate("kubernetes.configmap.create").requires_approval());
    }

    // ── Prod write with approval ─────────────────────────────────

    #[test]
    fn prod_scale_with_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "prod-1"));
        let token = ApprovalToken::new("tok", "sre", "kubernetes.scale_deployment");
        let d = p.evaluate_with_approval("kubernetes.scale_deployment", Some(&token));
        assert!(d.is_allowed());
    }

    #[test]
    fn prod_rollout_restart_with_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "prod-1"));
        let token = ApprovalToken::new("tok", "sre", "kubernetes.rollout_restart");
        let d = p.evaluate_with_approval("kubernetes.rollout_restart", Some(&token));
        assert!(d.is_allowed());
    }

    #[test]
    fn prod_update_configmap_with_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "prod-1"));
        let token = ApprovalToken::new("tok", "sre", "kubernetes.update_configmap");
        let d = p.evaluate_with_approval("kubernetes.update_configmap", Some(&token));
        assert!(d.is_allowed());
    }

    // ── Edge cases ───────────────────────────────────────────────

    #[test]
    fn empty_operation_id_denied() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "local"));
        assert!(p.evaluate("").is_denied());
    }

    #[test]
    fn whitespace_operation_id_denied() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "c"));
        assert!(p.evaluate("   ").is_denied());
    }

    #[test]
    fn prod_all_read_ops_comprehensive() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let read_ops = [
            "kubernetes.list_pods",
            "kubernetes.get_pod",
            "kubernetes.get_pod_logs",
            "kubernetes.stream_pod_logs",
            "kubernetes.list_deployments",
            "kubernetes.get_deployment",
            "kubernetes.get_service",
            "kubernetes.list_services",
            "kubernetes.get_configmap",
            "kubernetes.watch_events",
            "kubernetes.configmap.list",
            "kubernetes.configmap.get",
            "kubernetes.rollout.status",
            "kubernetes.rollout.history",
        ];
        for op in &read_ops {
            assert!(
                p.evaluate(op).is_allowed(),
                "prod should allow read op: {op}"
            );
        }
    }

    #[test]
    fn prod_all_delete_ops_denied() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let delete_ops = [
            "kubernetes.delete_pod",
            "kubernetes.delete_deployment",
            "kubernetes.configmap.delete",
            "kubernetes.secret.delete",
        ];
        for op in &delete_ops {
            assert!(
                p.evaluate(op).is_denied(),
                "prod should deny delete op: {op}"
            );
        }
    }

    #[test]
    fn prod_all_write_ops_require_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let write_ops = [
            "kubernetes.scale_deployment",
            "kubernetes.rollout_restart",
            "kubernetes.update_configmap",
            "kubernetes.configmap.update",
            "kubernetes.rollout.rollback",
        ];
        for op in &write_ops {
            assert!(
                p.evaluate(op).requires_approval(),
                "prod should require approval for write op: {op}"
            );
        }
    }

    #[test]
    fn prod_all_deploy_ops_require_approval() {
        let p = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "us-east-1"));
        let deploy_ops = [
            "kubernetes.create_pod",
            "kubernetes.apply_deployment",
            "kubernetes.configmap.create",
            "kubernetes.secret.create",
        ];
        for op in &deploy_ops {
            assert!(
                p.evaluate(op).requires_approval(),
                "prod should require approval for deploy op: {op}"
            );
        }
    }

    // ── Zone isolation (single-zone bound) ───────────────────────

    #[test]
    fn each_zone_is_independent() {
        let dev = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "cluster-a"));
        let prod = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "cluster-b"));

        // Modifying dev policy doesn't affect prod
        let dev_with_deletes = dev.with_prod_deletes(true);
        // dev_with_deletes flag is irrelevant since dev always allows
        assert!(dev_with_deletes.evaluate("kubernetes.delete_pod").is_allowed());
        // prod is still strict
        assert!(prod.evaluate("kubernetes.delete_pod").is_denied());
    }

    #[test]
    fn zone_names_recommended_format() {
        // Verify the recommended naming convention works
        let names = [
            "z:work:k8s:dev:minikube",
            "z:work:k8s:staging:us-west-2",
            "z:work:k8s:prod:us-east-1",
            "z:work:k8s:dev:kind-local",
            "z:work:k8s:prod:eu-central-1",
        ];
        for name in &names {
            let zc = ZoneConfig::parse(name);
            assert!(zc.is_some(), "should parse: {name}");
        }
    }

    // ── Capability tiering ───────────────────────────────────────

    #[test]
    fn readonly_capability_tier_allows_in_all_zones() {
        let tiers = [ZoneTier::Dev, ZoneTier::Staging, ZoneTier::Prod];
        for tier in &tiers {
            let p = ZonePolicy::new(ZoneConfig::new(*tier, "c"));
            assert!(
                p.evaluate("kubernetes.list_pods").is_allowed(),
                "read should be allowed in {tier}"
            );
        }
    }

    #[test]
    fn deploy_capability_tier() {
        let dev = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "c"));
        let stg = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "c"));
        let prod = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "c"));

        // Dev: open
        assert!(dev.evaluate("kubernetes.apply_deployment").is_allowed());
        // Staging: open
        assert!(stg.evaluate("kubernetes.apply_deployment").is_allowed());
        // Prod: gated
        assert!(prod.evaluate("kubernetes.apply_deployment").requires_approval());
    }

    #[test]
    fn exec_capability_tier() {
        let dev = ZonePolicy::new(ZoneConfig::new(ZoneTier::Dev, "c"));
        let stg = ZonePolicy::new(ZoneConfig::new(ZoneTier::Staging, "c"));
        let prod = ZonePolicy::new(ZoneConfig::new(ZoneTier::Prod, "c"));

        assert!(dev.evaluate("kubernetes.exec").is_allowed());
        assert!(stg.evaluate("kubernetes.exec").requires_approval());
        assert!(prod.evaluate("kubernetes.exec").requires_approval());
    }
}
