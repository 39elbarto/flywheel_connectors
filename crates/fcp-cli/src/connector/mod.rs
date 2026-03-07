//! `fcp connector` command implementation.
//!
//! Agent-visible connector discovery for AI agents and operators.
//!
//! # Usage
//!
//! ```text
//! # List all connectors
//! fcp connector list
//! fcp connector list --zone z:private
//! fcp connector list --json
//!
//! # Get detailed connector info
//! fcp connector info fcp.twitter:social:v1
//! fcp connector info fcp.twitter:social:v1 --json
//!
//! # Get introspection data (tool schemas for AI agents)
//! fcp connector introspect fcp.twitter:social:v1
//! fcp connector introspect fcp.twitter:social:v1 --json
//! ```

pub mod types;

use anyhow::{Context as _, Result};
use clap::{Args, Subcommand};

use fcp_core::{
    AgentHint, ApprovalMode, CapabilityId, ConnectorHealth, HashAlgorithm,
    IdempotencyClass, RateLimitConfig, RateLimitDeclarations, RateLimitEnforcement, RateLimitPool,
    RateLimitScope, RateLimitUnit, RiskLevel, SafetyTier, SoftwareBillOfMaterials,
    SupplyChainAttestation, SupplyChainVerificationPolicy, VerificationDecision,
    VerificationPipeline,
};
use types::{
    AuthCapsDescriptor, ConnectorHealthDisplay, ConnectorInfo, ConnectorIntrospection,
    ConnectorListOutput, ConnectorMetricsInfo, ConnectorSummary, EventCapsDescriptor,
    EventDescriptor, EventSummary, OperationDescriptor, OperationSummary, RateLimitDescriptor,
    ResourceTypeDescriptor, SandboxInfo, ZoneConnectors,
};

/// Arguments for the `fcp connector` command.
#[derive(Args, Debug)]
pub struct ConnectorArgs {
    #[command(subcommand)]
    pub command: ConnectorCommand,
}

/// Connector subcommands.
#[derive(Subcommand, Debug)]
pub enum ConnectorCommand {
    /// List all registered connectors.
    ///
    /// Shows a summary of connectors with their status and operation counts.
    List(ListArgs),

    /// Show detailed information about a connector.
    ///
    /// Displays configuration, capabilities, operations, and health status.
    Info(InfoArgs),

    /// Get introspection data for AI agent consumption.
    ///
    /// Returns full tool schemas, AI hints, and capability requirements
    /// in a format designed for AI agent tool discovery.
    Introspect(IntrospectArgs),

    /// Pin a connector to a specific version (prevents auto-upgrade).
    Pin(PinArgs),

    /// Unpin a connector (re-enables auto-upgrade).
    Unpin(UnpinArgs),

    /// Manage staged rollouts (canary deployments).
    Rollout(RolloutArgs),

    /// Roll back a connector to a previous version.
    Rollback(RollbackArgs),

    /// Verify supply chain attestation and SBOM for a connector.
    ///
    /// Checks the attestation, SBOM, and policy gates, producing a
    /// verification evidence bundle as structured JSON.
    Verify(VerifyArgs),
}

/// Arguments for `fcp connector list`.
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Filter by zone (e.g., "z:private").
    #[arg(long, short = 'z')]
    pub zone: Option<String>,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `fcp connector info`.
#[derive(Args, Debug)]
pub struct InfoArgs {
    /// Connector ID (e.g., "fcp.twitter:social:v1").
    pub connector_id: String,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `fcp connector introspect`.
#[derive(Args, Debug)]
pub struct IntrospectArgs {
    /// Connector ID (e.g., "fcp.twitter:social:v1").
    pub connector_id: String,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Only show specific operations (comma-separated).
    #[arg(long)]
    pub operations: Option<String>,
}

/// Arguments for `fcp connector pin`.
#[derive(Args, Debug)]
pub struct PinArgs {
    /// Connector ID (e.g., "fcp.discord:messaging:v1").
    pub connector_id: String,

    /// Version to pin to (e.g., "1.2.3").
    #[arg(long)]
    pub version: String,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `fcp connector unpin`.
#[derive(Args, Debug)]
pub struct UnpinArgs {
    /// Connector ID (e.g., "fcp.discord:messaging:v1").
    pub connector_id: String,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `fcp connector rollout`.
#[derive(Args, Debug)]
pub struct RolloutArgs {
    #[command(subcommand)]
    pub command: RolloutCommand,
}

/// Rollout subcommands.
#[derive(Subcommand, Debug)]
pub enum RolloutCommand {
    /// Set canary percentage for a connector rollout.
    Set(RolloutSetArgs),

    /// Show current rollout status for a connector.
    Status(RolloutStatusArgs),
}

/// Arguments for `fcp connector rollout set`.
#[derive(Args, Debug)]
pub struct RolloutSetArgs {
    /// Connector ID (e.g., "fcp.discord:messaging:v1").
    pub connector_id: String,

    /// Canary percentage (0-100).
    #[arg(long)]
    pub canary: u8,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `fcp connector rollout status`.
#[derive(Args, Debug)]
pub struct RolloutStatusArgs {
    /// Connector ID (e.g., "fcp.discord:messaging:v1").
    pub connector_id: String,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `fcp connector verify`.
#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Connector ID (e.g., "fcp.discord:messaging:v1").
    pub connector_id: String,

    /// Path to attestation file (JSON).
    #[arg(long)]
    pub attestation: Option<String>,

    /// Path to SBOM file (JSON).
    #[arg(long)]
    pub sbom: Option<String>,

    /// Binary artifact digest (blake3-256:<hex>).
    #[arg(long)]
    pub digest: Option<String>,

    /// Minimum SLSA level required (0-4).
    #[arg(long, default_value_t = 0)]
    pub min_slsa_level: u8,

    /// Allow unsigned artifacts (dev mode only).
    #[arg(long, default_value_t = false)]
    pub allow_unsigned: bool,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `fcp connector rollback`.
#[derive(Args, Debug)]
pub struct RollbackArgs {
    /// Connector ID (e.g., "fcp.discord:messaging:v1").
    pub connector_id: String,

    /// Version to roll back to.
    #[arg(long)]
    pub to: String,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Run the connector command.
pub fn run(args: &ConnectorArgs) -> Result<()> {
    match &args.command {
        ConnectorCommand::List(list_args) => run_list(list_args),
        ConnectorCommand::Info(info_args) => run_info(info_args),
        ConnectorCommand::Introspect(introspect_args) => run_introspect(introspect_args),
        ConnectorCommand::Pin(pin_args) => run_pin(pin_args),
        ConnectorCommand::Unpin(unpin_args) => run_unpin(unpin_args),
        ConnectorCommand::Rollout(rollout_args) => run_rollout(rollout_args),
        ConnectorCommand::Rollback(rollback_args) => run_rollback(rollback_args),
        ConnectorCommand::Verify(verify_args) => run_verify(verify_args),
    }
}

fn run_list(args: &ListArgs) -> Result<()> {
    // TODO: Connect to mesh node and query registry.
    // For now, we simulate output for demonstration.
    let output = simulate_list_output(args.zone.as_deref());

    if args.json {
        let json = serde_json::to_string_pretty(&output)?;
        println!("{json}");
    } else {
        print_list_human_readable(&output);
    }

    Ok(())
}

fn run_info(args: &InfoArgs) -> Result<()> {
    // TODO: Connect to mesh node and query registry.
    let info = simulate_connector_info(&args.connector_id)?;

    if args.json {
        let json = serde_json::to_string_pretty(&info)?;
        println!("{json}");
    } else {
        print_info_human_readable(&info);
    }

    Ok(())
}

fn run_introspect(args: &IntrospectArgs) -> Result<()> {
    // TODO: Connect to mesh node and query registry.
    let introspection = simulate_introspection(&args.connector_id, args.operations.as_deref())?;

    if args.json {
        let json = serde_json::to_string_pretty(&introspection)?;
        println!("{json}");
    } else {
        print_introspection_human_readable(&introspection);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulated data (to be replaced with real registry queries)
// ─────────────────────────────────────────────────────────────────────────────

fn simulate_list_output(zone_filter: Option<&str>) -> ConnectorListOutput {
    let all_connectors = vec![
        ZoneConnectors {
            zone_id: "z:private".to_string(),
            connectors: vec![
                ConnectorSummary {
                    id: "fcp.twitter:social:v1".to_string(),
                    name: "Twitter/X".to_string(),
                    description: Some("Social media connector".to_string()),
                    version: "1.2.0".to_string(),
                    categories: vec!["social".to_string()],
                    tool_count: 12,
                    max_safety_tier: SafetyTier::Risky,
                    enabled: true,
                    health: ConnectorHealth::healthy(),
                },
                ConnectorSummary {
                    id: "fcp.discord:social:v1".to_string(),
                    name: "Discord".to_string(),
                    description: Some("Discord messaging connector".to_string()),
                    version: "1.1.0".to_string(),
                    categories: vec!["social".to_string(), "messaging".to_string()],
                    tool_count: 18,
                    max_safety_tier: SafetyTier::Risky,
                    enabled: true,
                    health: ConnectorHealth::healthy(),
                },
                ConnectorSummary {
                    id: "fcp.telegram:messaging:v1".to_string(),
                    name: "Telegram".to_string(),
                    description: Some("Telegram messaging connector".to_string()),
                    version: "1.0.0".to_string(),
                    categories: vec!["messaging".to_string()],
                    tool_count: 15,
                    max_safety_tier: SafetyTier::Risky,
                    enabled: true,
                    health: ConnectorHealth::degraded("Rate limited"),
                },
            ],
        },
        ZoneConnectors {
            zone_id: "z:work".to_string(),
            connectors: vec![
                ConnectorSummary {
                    id: "fcp.openai:ai:v1".to_string(),
                    name: "OpenAI".to_string(),
                    description: Some("OpenAI API connector".to_string()),
                    version: "2.0.0".to_string(),
                    categories: vec!["ai".to_string()],
                    tool_count: 8,
                    max_safety_tier: SafetyTier::Dangerous,
                    enabled: true,
                    health: ConnectorHealth::healthy(),
                },
                ConnectorSummary {
                    id: "fcp.anthropic:ai:v1".to_string(),
                    name: "Anthropic".to_string(),
                    description: Some("Anthropic Claude connector".to_string()),
                    version: "1.5.0".to_string(),
                    categories: vec!["ai".to_string()],
                    tool_count: 6,
                    max_safety_tier: SafetyTier::Dangerous,
                    enabled: true,
                    health: ConnectorHealth::healthy(),
                },
            ],
        },
    ];

    let filtered: Vec<ZoneConnectors> = if let Some(zone) = zone_filter {
        all_connectors
            .into_iter()
            .filter(|z| z.zone_id == zone)
            .collect()
    } else {
        all_connectors
    };

    let total: usize = filtered.iter().map(|z| z.connectors.len()).sum();

    ConnectorListOutput {
        total,
        by_zone: filtered,
    }
}

#[allow(clippy::too_many_lines)] // Static connector simulation is inherently verbose
fn simulate_connector_info(connector_id: &str) -> Result<ConnectorInfo> {
    // Simulate looking up the connector
    match connector_id {
        "fcp.twitter:social:v1" => {
            let rate_limits = RateLimitDeclarations {
                limits: vec![
                    RateLimitPool {
                        id: "twitter_api".to_string(),
                        description: "Twitter API request pool".to_string(),
                        config: RateLimitConfig {
                            requests: 180,
                            window: std::time::Duration::from_secs(900),
                            burst: Some(18),
                            unit: RateLimitUnit::Requests,
                        },
                        enforcement: RateLimitEnforcement::Hard,
                        scope: RateLimitScope::Credential,
                    },
                    RateLimitPool {
                        id: "twitter_write".to_string(),
                        description: "Twitter write operations".to_string(),
                        config: RateLimitConfig {
                            requests: 300,
                            window: std::time::Duration::from_secs(10800),
                            burst: Some(30),
                            unit: RateLimitUnit::Requests,
                        },
                        enforcement: RateLimitEnforcement::Hard,
                        scope: RateLimitScope::Credential,
                    },
                ],
                tool_pool_map: std::collections::HashMap::from([
                    (
                        "twitter.get_timeline".to_string(),
                        vec!["twitter_api".to_string()],
                    ),
                    (
                        "twitter.post_tweet".to_string(),
                        vec!["twitter_write".to_string()],
                    ),
                    (
                        "twitter.send_dm".to_string(),
                        vec!["twitter_write".to_string()],
                    ),
                ]),
            };

            Ok(ConnectorInfo {
            id: "fcp.twitter:social:v1".to_string(),
            name: "Twitter/X Connector".to_string(),
            version: "1.2.0".to_string(),
            description: "Bidirectional connector for Twitter/X social platform. Supports reading timelines, posting tweets, direct messages, and real-time streaming.".to_string(),
            archetype: "bidirectional".to_string(),
            runtime_format: "wasi".to_string(),
            home_zone: "z:private".to_string(),
            allowed_source_zones: vec!["z:private".to_string(), "z:work".to_string()],
            required_capabilities: vec![
                CapabilityId::new("twitter:read:tweets").expect("valid capability id"),
                CapabilityId::new("twitter:read:profile").expect("valid capability id"),
            ],
            optional_capabilities: vec![
                CapabilityId::new("twitter:write:tweets").expect("valid capability id"),
                CapabilityId::new("twitter:write:dms").expect("valid capability id"),
                CapabilityId::new("twitter:read:dms").expect("valid capability id"),
            ],
            operations: vec![
                OperationSummary {
                    id: "twitter.get_timeline".to_string(),
                    summary: "Get home timeline".to_string(),
                    capability: CapabilityId::new("twitter:read:tweets")
                        .expect("valid capability id"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                },
                OperationSummary {
                    id: "twitter.post_tweet".to_string(),
                    summary: "Post a tweet".to_string(),
                    capability: CapabilityId::new("twitter:write:tweets")
                        .expect("valid capability id"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                },
                OperationSummary {
                    id: "twitter.send_dm".to_string(),
                    summary: "Send a direct message".to_string(),
                    capability: CapabilityId::new("twitter:write:dms").expect("valid capability id"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                },
            ],
            rate_limits: Some(rate_limits),
            events: vec![
                EventSummary {
                    topic: "tweets.new".to_string(),
                    requires_ack: true,
                },
                EventSummary {
                    topic: "dms.new".to_string(),
                    requires_ack: true,
                },
            ],
            sandbox: SandboxInfo {
                profile: "strict".to_string(),
                memory_mb: 64,
                cpu_percent: 25,
                network_access: true,
                allowed_hosts: vec!["api.twitter.com".to_string(), "api.x.com".to_string()],
            },
            status: ConnectorHealth::healthy(),
            metrics: Some(ConnectorMetricsInfo {
                requests_total: 15234,
                requests_success: 15100,
                requests_error: 134,
                events_emitted: 8923,
                latency_p50_ms: 42,
                latency_p99_ms: 187,
            }),
            publisher: Some("Flywheel Labs".to_string()),
            signed: true,
            attestations: vec!["in-toto".to_string(), "reproducible-build".to_string()],
        })
        }
        _ => anyhow::bail!("Connector not found: {connector_id}"),
    }
}

#[allow(clippy::too_many_lines)] // Static connector simulation is inherently verbose
fn simulate_introspection(
    connector_id: &str,
    operations_filter: Option<&str>,
) -> Result<ConnectorIntrospection> {
    match connector_id {
        "fcp.twitter:social:v1" => {
            let mut operations = vec![
                OperationDescriptor {
                    id: "twitter.get_timeline".to_string(),
                    summary: "Get the authenticated user's home timeline".to_string(),
                    description: Some("Retrieves recent tweets from the user's home timeline, including tweets from followed accounts and algorithmically recommended content.".to_string()),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "count": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 200,
                                "default": 20,
                                "description": "Number of tweets to retrieve"
                            },
                            "since_id": {
                                "type": "string",
                                "description": "Returns tweets newer than this ID"
                            },
                            "max_id": {
                                "type": "string",
                                "description": "Returns tweets older than this ID"
                            }
                        }
                    }),
                    output_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "tweets": {
                                "type": "array",
                                "items": {"$ref": "#/definitions/Tweet"}
                            },
                            "next_cursor": {"type": "string"}
                        }
                    }),
                    capability: CapabilityId::new("twitter:read:tweets")
                        .expect("valid capability id"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::BestEffort,
                    ai_hints: AgentHint {
                        when_to_use: "When the user wants to see recent tweets or catch up on their timeline".to_string(),
                        common_mistakes: vec![
                            "Requesting too many tweets at once (use pagination)".to_string(),
                            "Not handling rate limits gracefully".to_string(),
                        ],
                        examples: vec![
                            r#"{"count": 20}"#.to_string(),
                            r#"{"count": 50, "since_id": "1234567890"}"#.to_string(),
                        ],
                        related: vec![
                            CapabilityId::new("twitter:read:user_tweets")
                                .expect("valid capability id"),
                        ],
                    },
                    rate_limit: Some(RateLimitDescriptor {
                        requests: 180,
                        period_secs: 900,
                        formatted: "180/15min".to_string(),
                    }),
                    requires_approval: None,
                },
                OperationDescriptor {
                    id: "twitter.post_tweet".to_string(),
                    summary: "Post a new tweet".to_string(),
                    description: Some("Posts a new tweet to the authenticated user's timeline. Supports text, media attachments, and reply threading.".to_string()),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "text": {
                                "type": "string",
                                "maxLength": 280,
                                "description": "Tweet text content"
                            },
                            "reply_to_id": {
                                "type": "string",
                                "description": "Tweet ID to reply to"
                            },
                            "media_ids": {
                                "type": "array",
                                "items": {"type": "string"},
                                "maxItems": 4,
                                "description": "Media attachment IDs"
                            }
                        },
                        "required": ["text"]
                    }),
                    output_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "tweet_id": {"type": "string"},
                            "created_at": {"type": "string", "format": "date-time"},
                            "text": {"type": "string"}
                        }
                    }),
                    capability: CapabilityId::new("twitter:write:tweets")
                        .expect("valid capability id"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Only when the user explicitly requests to post a tweet. Always confirm content before posting.".to_string(),
                        common_mistakes: vec![
                            "Posting without explicit user confirmation".to_string(),
                            "Exceeding character limit".to_string(),
                            "Not handling duplicate tweet errors".to_string(),
                        ],
                        examples: vec![
                            r#"{"text": "Hello world!"}"#.to_string(),
                            r#"{"text": "Replying to your tweet", "reply_to_id": "1234567890"}"#.to_string(),
                        ],
                        related: vec![
                            CapabilityId::new("twitter:delete:tweets")
                                .expect("valid capability id"),
                        ],
                    },
                    rate_limit: Some(RateLimitDescriptor {
                        requests: 300,
                        period_secs: 10800,
                        formatted: "300/3hr".to_string(),
                    }),
                    requires_approval: Some(ApprovalMode::Interactive),
                },
                OperationDescriptor {
                    id: "twitter.send_dm".to_string(),
                    summary: "Send a direct message".to_string(),
                    description: Some("Sends a direct message to another user. The recipient must allow DMs from the sender.".to_string()),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "recipient_id": {
                                "type": "string",
                                "description": "User ID of the recipient"
                            },
                            "text": {
                                "type": "string",
                                "maxLength": 10000,
                                "description": "Message text"
                            }
                        },
                        "required": ["recipient_id", "text"]
                    }),
                    output_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "message_id": {"type": "string"},
                            "created_at": {"type": "string", "format": "date-time"}
                        }
                    }),
                    capability: CapabilityId::new("twitter:write:dms")
                        .expect("valid capability id"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "When the user wants to send a private message to someone on Twitter".to_string(),
                        common_mistakes: vec![
                            "Sending without user confirmation".to_string(),
                            "Messaging users who have DMs disabled".to_string(),
                        ],
                        examples: vec![
                            r#"{"recipient_id": "12345", "text": "Hello!"}"#.to_string(),
                        ],
                        related: vec![
                            CapabilityId::new("twitter:read:dms")
                                .expect("valid capability id"),
                        ],
                    },
                    rate_limit: Some(RateLimitDescriptor {
                        requests: 1000,
                        period_secs: 86400,
                        formatted: "1000/day".to_string(),
                    }),
                    requires_approval: Some(ApprovalMode::Interactive),
                },
            ];

            // Apply operation filter if specified
            if let Some(filter) = operations_filter {
                let filter_ops: Vec<&str> = filter.split(',').map(str::trim).collect();
                operations.retain(|op| filter_ops.iter().any(|f| op.id.contains(f)));
            }

            let rate_limits = RateLimitDeclarations {
                limits: vec![
                    RateLimitPool {
                        id: "twitter_api".to_string(),
                        description: "Twitter API request pool".to_string(),
                        config: RateLimitConfig {
                            requests: 180,
                            window: std::time::Duration::from_secs(900),
                            burst: Some(18),
                            unit: RateLimitUnit::Requests,
                        },
                        enforcement: RateLimitEnforcement::Hard,
                        scope: RateLimitScope::Credential,
                    },
                    RateLimitPool {
                        id: "twitter_write".to_string(),
                        description: "Twitter write operations".to_string(),
                        config: RateLimitConfig {
                            requests: 300,
                            window: std::time::Duration::from_secs(10800),
                            burst: Some(30),
                            unit: RateLimitUnit::Requests,
                        },
                        enforcement: RateLimitEnforcement::Hard,
                        scope: RateLimitScope::Credential,
                    },
                ],
                tool_pool_map: std::collections::HashMap::from([
                    (
                        "twitter.get_timeline".to_string(),
                        vec!["twitter_api".to_string()],
                    ),
                    (
                        "twitter.post_tweet".to_string(),
                        vec!["twitter_write".to_string()],
                    ),
                    (
                        "twitter.send_dm".to_string(),
                        vec!["twitter_write".to_string()],
                    ),
                ]),
            };

            Ok(ConnectorIntrospection {
                connector_id: "fcp.twitter:social:v1".to_string(),
                version: "1.2.0".to_string(),
                operations,
                events: vec![
                    EventDescriptor {
                        topic: "tweets.new".to_string(),
                        schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "tweet_id": {"type": "string"},
                                "author_id": {"type": "string"},
                                "text": {"type": "string"},
                                "created_at": {"type": "string", "format": "date-time"}
                            }
                        }),
                        requires_ack: true,
                    },
                    EventDescriptor {
                        topic: "dms.new".to_string(),
                        schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "message_id": {"type": "string"},
                                "sender_id": {"type": "string"},
                                "text": {"type": "string"},
                                "created_at": {"type": "string", "format": "date-time"}
                            }
                        }),
                        requires_ack: true,
                    },
                ],
                rate_limits: Some(rate_limits),
                resource_types: vec![
                    ResourceTypeDescriptor {
                        name: "Tweet".to_string(),
                        uri_pattern: "fcp://fcp.twitter/tweet/{id}".to_string(),
                        schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "text": {"type": "string"},
                                "author_id": {"type": "string"},
                                "created_at": {"type": "string", "format": "date-time"},
                                "metrics": {
                                    "type": "object",
                                    "properties": {
                                        "likes": {"type": "integer"},
                                        "retweets": {"type": "integer"},
                                        "replies": {"type": "integer"}
                                    }
                                }
                            }
                        }),
                    },
                    ResourceTypeDescriptor {
                        name: "User".to_string(),
                        uri_pattern: "fcp://fcp.twitter/user/{id}".to_string(),
                        schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "username": {"type": "string"},
                                "display_name": {"type": "string"},
                                "verified": {"type": "boolean"},
                                "followers_count": {"type": "integer"}
                            }
                        }),
                    },
                ],
                auth_caps: Some(AuthCapsDescriptor {
                    methods: vec!["oauth2".to_string()],
                    supports_refresh: true,
                }),
                event_caps: Some(EventCapsDescriptor {
                    streaming: true,
                    replay: true,
                    min_buffer_events: 1000,
                    max_replay_window_secs: 3600,
                }),
            })
        }
        _ => anyhow::bail!("Connector not found: {connector_id}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Human-readable output formatting
// ─────────────────────────────────────────────────────────────────────────────

fn print_list_human_readable(output: &ConnectorListOutput) {
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";
    let dim = "\x1b[2m";

    println!();
    println!("{bold}Registered Connectors{reset}");
    println!("=====================");
    println!();
    println!("Total: {}", output.total);
    println!();

    for zone in &output.by_zone {
        println!("{bold}{}{reset}", zone.zone_id);
        println!("{}", "-".repeat(zone.zone_id.len()));

        for conn in &zone.connectors {
            let color = conn.health.ansi_color();
            let symbol = conn.health.symbol();
            let enabled_str = if conn.enabled { "enabled" } else { "disabled" };
            let categories = conn.categories.join(", ");

            println!(
                "  {color}{symbol}{reset} {bold}{}{reset} v{} {dim}({}){reset}",
                conn.name, conn.version, categories
            );
            println!(
                "    {dim}ID:{reset} {}  {dim}Tools:{reset} {}  {dim}[{}]{reset}",
                conn.id, conn.tool_count, enabled_str
            );
        }
        println!();
    }
}

#[allow(clippy::too_many_lines)] // CLI output formatting is intentionally verbose
fn print_info_human_readable(info: &ConnectorInfo) {
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";
    let dim = "\x1b[2m";
    let cyan = "\x1b[36m";
    let color = info.status.ansi_color();
    let symbol = info.status.symbol();
    let label = info.status.label();

    println!();
    println!("{bold}{}{reset}", info.name);
    println!("{}", "=".repeat(info.name.len()));
    println!();
    println!("{}", info.description);
    println!();

    println!("{bold}Identity{reset}");
    println!("  ID:       {}", info.id);
    println!("  Version:  {}", info.version);
    println!("  Type:     {} ({})", info.archetype, info.runtime_format);
    println!("  Status:   {color}{symbol} {label}{reset}");
    println!();

    println!("{bold}Zone Configuration{reset}");
    println!("  Home Zone:      {}", info.home_zone);
    println!("  Source Zones:   {}", info.allowed_source_zones.join(", "));
    println!();

    println!("{bold}Capabilities{reset}");
    println!("  Required:");
    for cap in &info.required_capabilities {
        println!("    - {}", cap.as_str());
    }
    if !info.optional_capabilities.is_empty() {
        println!("  Optional:");
        for cap in &info.optional_capabilities {
            println!("    - {}", cap.as_str());
        }
    }
    println!();

    println!("{bold}Operations{reset} ({})", info.operations.len());
    for op in &info.operations {
        let risk_color = match op.risk_level {
            RiskLevel::Low => "\x1b[32m",
            RiskLevel::Medium => "\x1b[33m",
            RiskLevel::High | RiskLevel::Critical => "\x1b[31m",
        };
        println!(
            "  {dim}{}{reset}: {} {risk_color}[{} / {}]{reset}",
            op.id,
            op.summary,
            risk_level_label(op.risk_level),
            safety_tier_label(op.safety_tier)
        );
    }
    println!();

    if let Some(rate_limits) = &info.rate_limits {
        println!("{bold}Rate Limits{reset}");
        if rate_limits.limits.is_empty() {
            println!("  {dim}No pools declared{reset}");
        } else {
            for pool in &rate_limits.limits {
                let window_secs = pool.config.window.as_secs();
                let burst = pool
                    .config
                    .burst
                    .map_or_else(|| "none".to_string(), |b| b.to_string());
                println!("  {cyan}{bold}{}{reset}", pool.id);
                if !pool.description.is_empty() {
                    println!("    {dim}{}{}", pool.description, reset);
                }
                println!(
                    "    {dim}Limit:{reset} {} per {}s (burst {})",
                    pool.config.requests, window_secs, burst
                );
                println!(
                    "    {dim}Unit:{reset} {}  {dim}Enforcement:{reset} {}  {dim}Scope:{reset} {}",
                    rate_limit_unit_label(pool.config.unit),
                    rate_limit_enforcement_label(pool.enforcement),
                    rate_limit_scope_label(pool.scope)
                );
            }
        }

        if !rate_limits.tool_pool_map.is_empty() {
            println!();
            println!("{bold}Tool -> Pools{reset}");
            for (tool, pools) in &rate_limits.tool_pool_map {
                println!("  {tool}: {}", pools.join(", "));
            }
        }
        println!();
    }

    if !info.events.is_empty() {
        println!("{bold}Events{reset}");
        for event in &info.events {
            let ack = if event.requires_ack { " (ack)" } else { "" };
            println!("  - {}{ack}", event.topic);
        }
        println!();
    }

    println!("{bold}Sandbox{reset}");
    println!("  Profile:    {}", info.sandbox.profile);
    println!("  Memory:     {} MB", info.sandbox.memory_mb);
    println!("  CPU:        {}%", info.sandbox.cpu_percent);
    if info.sandbox.network_access {
        println!("  Network:    {}", info.sandbox.allowed_hosts.join(", "));
    } else {
        println!("  Network:    disabled");
    }
    println!();

    if let Some(metrics) = &info.metrics {
        println!("{bold}Metrics{reset}");
        println!(
            "  Requests:   {} total ({} success, {} error)",
            metrics.requests_total, metrics.requests_success, metrics.requests_error
        );
        println!("  Events:     {} emitted", metrics.events_emitted);
        println!(
            "  Latency:    p50={}ms, p99={}ms",
            metrics.latency_p50_ms, metrics.latency_p99_ms
        );
        println!();
    }

    if info.signed {
        println!("{bold}Supply Chain{reset}");
        if let Some(publisher) = &info.publisher {
            println!("  Publisher:    {publisher}");
        }
        println!("  Signed:       yes");
        if !info.attestations.is_empty() {
            println!("  Attestations: {}", info.attestations.join(", "));
        }
        println!();
    }
}

#[allow(clippy::too_many_lines)]
fn print_introspection_human_readable(intro: &ConnectorIntrospection) {
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";
    let dim = "\x1b[2m";
    let cyan = "\x1b[36m";

    println!();
    println!(
        "{bold}Introspection: {}{reset} v{}",
        intro.connector_id, intro.version
    );
    println!("{}", "=".repeat(50));
    println!();

    if let Some(rate_limits) = &intro.rate_limits {
        println!("{bold}Rate Limits{reset}");
        if rate_limits.limits.is_empty() {
            println!("  {dim}No pools declared{reset}");
        } else {
            for pool in &rate_limits.limits {
                let window_secs = pool.config.window.as_secs();
                let burst = pool
                    .config
                    .burst
                    .map_or_else(|| "none".to_string(), |b| b.to_string());
                println!("  {cyan}{bold}{}{reset}", pool.id);
                if !pool.description.is_empty() {
                    println!("    {dim}{}{}", pool.description, reset);
                }
                println!(
                    "    {dim}Limit:{reset} {} per {}s (burst {})",
                    pool.config.requests, window_secs, burst
                );
                println!(
                    "    {dim}Unit:{reset} {}  {dim}Enforcement:{reset} {}  {dim}Scope:{reset} {}",
                    rate_limit_unit_label(pool.config.unit),
                    rate_limit_enforcement_label(pool.enforcement),
                    rate_limit_scope_label(pool.scope)
                );
            }
        }

        if !rate_limits.tool_pool_map.is_empty() {
            println!();
            println!("{bold}Tool -> Pools{reset}");
            for (tool, pools) in &rate_limits.tool_pool_map {
                println!("  {tool}: {}", pools.join(", "));
            }
        }
        println!();
    }

    println!("{bold}Operations{reset} ({})", intro.operations.len());
    println!();

    for op in &intro.operations {
        let risk_color = match op.risk_level {
            RiskLevel::Low => "\x1b[32m",
            RiskLevel::Medium => "\x1b[33m",
            RiskLevel::High | RiskLevel::Critical => "\x1b[31m",
        };

        println!("{cyan}{bold}{}{reset}", op.id);
        println!("  {}", op.summary);
        if let Some(desc) = &op.description {
            println!("  {dim}{desc}{reset}");
        }
        println!();
        println!(
            "  {dim}Capability:{reset} {}  {risk_color}Risk: {} / {}{reset}",
            op.capability.as_str(),
            risk_level_label(op.risk_level),
            safety_tier_label(op.safety_tier)
        );
        println!(
            "  {dim}Idempotency:{reset} {}",
            idempotency_label(op.idempotency)
        );

        if let Some(approval) = &op.requires_approval {
            println!("  {dim}Approval:{reset} {}", approval_label(*approval));
        }

        if let Some(rate) = &op.rate_limit {
            println!("  {dim}Rate Limit:{reset} {}", rate.formatted);
        }

        println!();
        println!("  {dim}Input Schema:{reset}");
        let schema_str = serde_json::to_string_pretty(&op.input_schema).unwrap_or_default();
        for line in schema_str.lines() {
            println!("    {line}");
        }

        println!();
        println!("  {dim}AI Hints:{reset}");
        println!("    When to use: {}", op.ai_hints.when_to_use);
        if !op.ai_hints.common_mistakes.is_empty() {
            println!("    Common mistakes:");
            for mistake in &op.ai_hints.common_mistakes {
                println!("      - {mistake}");
            }
        }
        if !op.ai_hints.examples.is_empty() {
            println!("    Examples:");
            for example in &op.ai_hints.examples {
                println!("      {example}");
            }
        }
        if !op.ai_hints.related.is_empty() {
            println!("    Related capabilities:");
            for related in &op.ai_hints.related {
                println!("      - {}", related.as_str());
            }
        }

        println!();
        println!("  {}", "-".repeat(40));
        println!();
    }

    if !intro.events.is_empty() {
        println!("{bold}Event Topics{reset}");
        for event in &intro.events {
            let ack = if event.requires_ack {
                " (ack required)"
            } else {
                ""
            };
            println!("  {cyan}{}{reset}{ack}", event.topic);
        }
        println!();
    }

    if !intro.resource_types.is_empty() {
        println!("{bold}Resource Types{reset}");
        for res in &intro.resource_types {
            println!("  {cyan}{}{reset}: {}", res.name, res.uri_pattern);
        }
        println!();
    }

    if let Some(event_caps) = &intro.event_caps {
        println!("{bold}Event Capabilities{reset}");
        println!(
            "  Streaming: {}  Replay: {}",
            if event_caps.streaming { "yes" } else { "no" },
            if event_caps.replay { "yes" } else { "no" }
        );
        println!(
            "  Buffer: {} events, Replay window: {}s",
            event_caps.min_buffer_events, event_caps.max_replay_window_secs
        );
        println!();
    }
}

const fn risk_level_label(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

const fn safety_tier_label(tier: SafetyTier) -> &'static str {
    match tier {
        SafetyTier::Safe => "safe",
        SafetyTier::Risky => "risky",
        SafetyTier::Dangerous => "dangerous",
        SafetyTier::Critical => "critical",
        SafetyTier::Forbidden => "forbidden",
    }
}

const fn idempotency_label(class: IdempotencyClass) -> &'static str {
    match class {
        IdempotencyClass::None => "none",
        IdempotencyClass::BestEffort => "best_effort",
        IdempotencyClass::Strict => "strict",
    }
}

const fn approval_label(mode: ApprovalMode) -> &'static str {
    match mode {
        ApprovalMode::None => "none",
        ApprovalMode::Policy => "policy",
        ApprovalMode::Interactive => "interactive",
        ApprovalMode::ElevationToken => "elevation_token",
    }
}

const fn rate_limit_unit_label(unit: RateLimitUnit) -> &'static str {
    match unit {
        RateLimitUnit::Requests => "requests",
        RateLimitUnit::Tokens => "tokens",
        RateLimitUnit::Bytes => "bytes",
        RateLimitUnit::Custom => "custom",
    }
}

const fn rate_limit_enforcement_label(enforcement: RateLimitEnforcement) -> &'static str {
    match enforcement {
        RateLimitEnforcement::Hard => "hard",
        RateLimitEnforcement::Soft => "soft",
        RateLimitEnforcement::Advisory => "advisory",
    }
}

const fn rate_limit_scope_label(scope: RateLimitScope) -> &'static str {
    match scope {
        RateLimitScope::Instance => "instance",
        RateLimitScope::Credential => "credential",
        RateLimitScope::Global => "global",
    }
}

// ── Supply Chain: verify ──────────────────────────────────────

/// JSON output for verify command.
#[derive(Debug, serde::Serialize)]
struct VerifyOutput {
    connector_id: String,
    decision: String,
    reason_code: String,
    artifact_digest: String,
    steps: Vec<VerifyStepOutput>,
    evidence_digest: String,
    policy: VerifyPolicyOutput,
}

#[derive(Debug, serde::Serialize)]
struct VerifyStepOutput {
    step: String,
    passed: bool,
    detail: String,
}

#[derive(Debug, serde::Serialize)]
struct VerifyPolicyOutput {
    require_attestation: bool,
    require_sbom: bool,
    min_slsa_level: u8,
    allow_unsigned: bool,
}

fn run_verify(args: &VerifyArgs) -> Result<()> {
    let policy = SupplyChainVerificationPolicy {
        require_attestation: args.attestation.is_some() || !args.allow_unsigned,
        require_sbom: args.sbom.is_some() || !args.allow_unsigned,
        min_slsa_level: args.min_slsa_level,
        trusted_builders: vec![],
        allow_unsigned: args.allow_unsigned,
        require_digest_match: args.digest.is_some(),
    };

    let attestation: Option<SupplyChainAttestation> = match &args.attestation {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read attestation file: {path}"))?;
            Some(serde_json::from_str(&content)
                .with_context(|| format!("invalid attestation JSON in {path}"))?)
        }
        None => None,
    };

    let sbom: Option<SoftwareBillOfMaterials> = match &args.sbom {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read SBOM file: {path}"))?;
            Some(serde_json::from_str(&content)
                .with_context(|| format!("invalid SBOM JSON in {path}"))?)
        }
        None => None,
    };

    let artifact_digest = args.digest.clone().unwrap_or_default();

    let pipeline = VerificationPipeline::new(policy.clone());
    let evidence = pipeline.verify(
        &artifact_digest,
        attestation.as_ref(),
        sbom.as_ref(),
    );

    let evidence_digest = evidence
        .content_hash(HashAlgorithm::Blake3_256)
        .map_err(|e| anyhow::anyhow!("evidence hash failed: {e}"))?;

    let output = VerifyOutput {
        connector_id: args.connector_id.clone(),
        decision: format!("{:?}", evidence.decision).to_lowercase(),
        reason_code: format!("{}", evidence.reason_code),
        artifact_digest: evidence.artifact_digest.clone(),
        steps: evidence
            .steps
            .iter()
            .map(|s| VerifyStepOutput {
                step: s.step.clone(),
                passed: s.passed,
                detail: s.detail.clone(),
            })
            .collect(),
        evidence_digest,
        policy: VerifyPolicyOutput {
            require_attestation: policy.require_attestation,
            require_sbom: policy.require_sbom,
            min_slsa_level: policy.min_slsa_level,
            allow_unsigned: policy.allow_unsigned,
        },
    };

    let allowed = evidence.decision == VerificationDecision::Allow;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else if allowed {
        println!("Verification PASSED for {}", args.connector_id);
        println!("  Reason: {}", output.reason_code);
        for step in &output.steps {
            let icon = if step.passed { "  pass" } else { "  FAIL" };
            println!("  {icon}: {} — {}", step.step, step.detail);
        }
        println!("  Evidence: {}", output.evidence_digest);
    } else {
        println!("Verification FAILED for {}", args.connector_id);
        println!("  Reason: {}", output.reason_code);
        for step in &output.steps {
            let icon = if step.passed { "  pass" } else { "  FAIL" };
            println!("  {icon}: {} — {}", step.step, step.detail);
        }
        println!("  Evidence: {}", output.evidence_digest);
    }

    if !allowed {
        std::process::exit(1);
    }

    Ok(())
}

// ── Lifecycle: pin/unpin/rollout/rollback ─────────────────────

/// JSON output for pin/unpin operations.
#[derive(Debug, serde::Serialize)]
struct PinOutput {
    connector_id: String,
    action: String,
    version: Option<String>,
    message: String,
}

/// JSON output for rollout status.
#[derive(Debug, serde::Serialize)]
struct RolloutStatusOutput {
    connector_id: String,
    state: String,
    version: String,
    canary_percent: u8,
    pinned: bool,
    health: String,
    message: String,
}

/// JSON output for rollback.
#[derive(Debug, serde::Serialize)]
struct RollbackOutput {
    connector_id: String,
    from_version: String,
    to_version: String,
    message: String,
}

fn run_pin(args: &PinArgs) -> Result<()> {
    // TODO: connect to host and execute pin via rollout controller.
    let version = semver::Version::parse(&args.version)
        .map_err(|e| anyhow::anyhow!("invalid semver version '{}': {e}", args.version))?;

    let output = PinOutput {
        connector_id: args.connector_id.clone(),
        action: "pin".to_string(),
        version: Some(version.to_string()),
        message: format!(
            "Connector {} pinned to version {version}. Auto-upgrade disabled.",
            args.connector_id
        ),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "Pinned {} to v{version}",
            args.connector_id
        );
        println!("  Auto-upgrade is now disabled for this connector.");
        println!("  Use `fcp connector unpin {}` to re-enable.", args.connector_id);
    }

    Ok(())
}

fn run_unpin(args: &UnpinArgs) -> Result<()> {
    // TODO: connect to host and execute unpin via rollout controller.
    let output = PinOutput {
        connector_id: args.connector_id.clone(),
        action: "unpin".to_string(),
        version: None,
        message: format!(
            "Connector {} unpinned. Auto-upgrade re-enabled.",
            args.connector_id
        ),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Unpinned {}", args.connector_id);
        println!("  Auto-upgrade is now re-enabled.");
    }

    Ok(())
}

fn run_rollout(args: &RolloutArgs) -> Result<()> {
    match &args.command {
        RolloutCommand::Set(set_args) => run_rollout_set(set_args),
        RolloutCommand::Status(status_args) => run_rollout_status(status_args),
    }
}

fn run_rollout_set(args: &RolloutSetArgs) -> Result<()> {
    if args.canary > 100 {
        anyhow::bail!("canary percentage must be 0-100, got {}", args.canary);
    }

    // TODO: connect to host and configure canary via rollout controller.
    let output = RolloutStatusOutput {
        connector_id: args.connector_id.clone(),
        state: "canary".to_string(),
        version: "pending".to_string(),
        canary_percent: args.canary,
        pinned: false,
        health: "unknown".to_string(),
        message: format!(
            "Canary set to {}% for {}.",
            args.canary, args.connector_id
        ),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "Rollout canary set to {}% for {}",
            args.canary, args.connector_id
        );
        println!("  Use `fcp connector rollout status {}` to monitor.", args.connector_id);
    }

    Ok(())
}

fn run_rollout_status(args: &RolloutStatusArgs) -> Result<()> {
    // TODO: connect to host and query rollout status.
    let output = RolloutStatusOutput {
        connector_id: args.connector_id.clone(),
        state: "production".to_string(),
        version: "1.0.0".to_string(),
        canary_percent: 0,
        pinned: false,
        health: "healthy".to_string(),
        message: format!("Connector {} is in production (v1.0.0).", args.connector_id),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Rollout status for {}", args.connector_id);
        println!("  State:   {}", output.state);
        println!("  Version: v{}", output.version);
        println!("  Health:  {}", output.health);
        println!("  Pinned:  {}", if output.pinned { "yes" } else { "no" });
        if output.canary_percent > 0 {
            println!("  Canary:  {}%", output.canary_percent);
        }
    }

    Ok(())
}

fn run_rollback(args: &RollbackArgs) -> Result<()> {
    let to_version = semver::Version::parse(&args.to)
        .map_err(|e| anyhow::anyhow!("invalid semver version '{}': {e}", args.to))?;

    // TODO: connect to host and execute rollback via rollout controller.
    let output = RollbackOutput {
        connector_id: args.connector_id.clone(),
        from_version: "current".to_string(),
        to_version: to_version.to_string(),
        message: format!(
            "Connector {} rolled back to v{to_version}.",
            args.connector_id
        ),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "Rolled back {} to v{to_version}",
            args.connector_id
        );
        println!("  Previous version will be deactivated.");
        println!("  Use `fcp connector rollout status {}` to verify.", args.connector_id);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_all_connectors() {
        let output = simulate_list_output(None);
        assert_eq!(output.total, 5);
        assert_eq!(output.by_zone.len(), 2);
    }

    #[test]
    fn list_filtered_by_zone() {
        let output = simulate_list_output(Some("z:private"));
        assert_eq!(output.total, 3);
        assert_eq!(output.by_zone.len(), 1);
        assert_eq!(output.by_zone[0].zone_id, "z:private");
    }

    #[test]
    fn list_empty_zone_filter() {
        let output = simulate_list_output(Some("z:nonexistent"));
        assert_eq!(output.total, 0);
        assert!(output.by_zone.is_empty());
    }

    #[test]
    fn info_known_connector() {
        let info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        assert_eq!(info.id, "fcp.twitter:social:v1");
        assert_eq!(info.archetype, "bidirectional");
        assert!(!info.operations.is_empty());
        assert!(info.rate_limits.is_some());
    }

    #[test]
    fn info_unknown_connector() {
        let result = simulate_connector_info("fcp.unknown:test:v1");
        assert!(result.is_err());
    }

    #[test]
    fn introspect_known_connector() {
        let intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        assert_eq!(intro.connector_id, "fcp.twitter:social:v1");
        assert_eq!(intro.operations.len(), 3);
        assert!(intro.event_caps.is_some());
        assert!(intro.rate_limits.is_some());
    }

    #[test]
    fn introspect_with_filter() {
        let intro = simulate_introspection("fcp.twitter:social:v1", Some("post_tweet")).unwrap();
        assert_eq!(intro.operations.len(), 1);
        assert_eq!(intro.operations[0].id, "twitter.post_tweet");
    }

    #[test]
    fn introspect_unknown_connector() {
        let result = simulate_introspection("fcp.unknown:test:v1", None);
        assert!(result.is_err());
    }

    // ---- label functions ----

    #[test]
    fn risk_level_labels() {
        assert_eq!(risk_level_label(RiskLevel::Low), "low");
        assert_eq!(risk_level_label(RiskLevel::Medium), "medium");
        assert_eq!(risk_level_label(RiskLevel::High), "high");
        assert_eq!(risk_level_label(RiskLevel::Critical), "critical");
    }

    #[test]
    fn safety_tier_labels() {
        assert_eq!(safety_tier_label(SafetyTier::Safe), "safe");
        assert_eq!(safety_tier_label(SafetyTier::Risky), "risky");
        assert_eq!(safety_tier_label(SafetyTier::Dangerous), "dangerous");
        assert_eq!(safety_tier_label(SafetyTier::Critical), "critical");
        assert_eq!(safety_tier_label(SafetyTier::Forbidden), "forbidden");
    }

    #[test]
    fn idempotency_labels() {
        assert_eq!(idempotency_label(IdempotencyClass::None), "none");
        assert_eq!(
            idempotency_label(IdempotencyClass::BestEffort),
            "best_effort"
        );
        assert_eq!(idempotency_label(IdempotencyClass::Strict), "strict");
    }

    #[test]
    fn approval_labels() {
        assert_eq!(approval_label(ApprovalMode::None), "none");
        assert_eq!(approval_label(ApprovalMode::Policy), "policy");
        assert_eq!(approval_label(ApprovalMode::Interactive), "interactive");
        assert_eq!(
            approval_label(ApprovalMode::ElevationToken),
            "elevation_token"
        );
    }

    #[test]
    fn rate_limit_unit_labels() {
        assert_eq!(rate_limit_unit_label(RateLimitUnit::Requests), "requests");
        assert_eq!(rate_limit_unit_label(RateLimitUnit::Tokens), "tokens");
        assert_eq!(rate_limit_unit_label(RateLimitUnit::Bytes), "bytes");
        assert_eq!(rate_limit_unit_label(RateLimitUnit::Custom), "custom");
    }

    #[test]
    fn rate_limit_enforcement_labels() {
        assert_eq!(
            rate_limit_enforcement_label(RateLimitEnforcement::Hard),
            "hard"
        );
        assert_eq!(
            rate_limit_enforcement_label(RateLimitEnforcement::Soft),
            "soft"
        );
        assert_eq!(
            rate_limit_enforcement_label(RateLimitEnforcement::Advisory),
            "advisory"
        );
    }

    #[test]
    fn rate_limit_scope_labels() {
        assert_eq!(rate_limit_scope_label(RateLimitScope::Instance), "instance");
        assert_eq!(
            rate_limit_scope_label(RateLimitScope::Credential),
            "credential"
        );
        assert_eq!(rate_limit_scope_label(RateLimitScope::Global), "global");
    }

    // ---- simulate_list_output details ----

    #[test]
    fn list_output_private_zone_has_three_connectors() {
        let output = simulate_list_output(Some("z:private"));
        assert_eq!(output.by_zone[0].connectors.len(), 3);
        assert_eq!(output.by_zone[0].connectors[0].id, "fcp.twitter:social:v1");
    }

    #[test]
    fn list_output_work_zone_has_two_connectors() {
        let output = simulate_list_output(Some("z:work"));
        assert_eq!(output.by_zone[0].connectors.len(), 2);
        assert!(
            output.by_zone[0]
                .connectors
                .iter()
                .any(|c| c.id == "fcp.openai:ai:v1")
        );
    }

    // ---- simulate_connector_info details ----

    #[test]
    fn info_twitter_has_rate_limits() {
        let info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        let rate_limits = info.rate_limits.unwrap();
        assert_eq!(rate_limits.limits.len(), 2);
        assert_eq!(rate_limits.limits[0].id, "twitter_api");
        assert_eq!(rate_limits.limits[0].config.requests, 180);
    }

    #[test]
    fn info_twitter_has_events() {
        let info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        assert_eq!(info.events.len(), 2);
        assert!(info.events.iter().any(|e| e.topic == "tweets.new"));
    }

    #[test]
    fn info_twitter_has_sandbox() {
        let info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        assert_eq!(info.sandbox.profile, "strict");
        assert!(info.sandbox.network_access);
        assert!(
            info.sandbox
                .allowed_hosts
                .contains(&"api.twitter.com".to_string())
        );
    }

    #[test]
    fn info_twitter_has_supply_chain() {
        let info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        assert!(info.signed);
        assert_eq!(info.publisher.as_deref(), Some("Flywheel Labs"));
        assert!(info.attestations.contains(&"in-toto".to_string()));
    }

    // ---- simulate_introspection details ----

    #[test]
    fn introspect_operations_have_schemas() {
        let intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        for op in &intro.operations {
            assert!(
                op.input_schema.is_object(),
                "op {} missing input_schema",
                op.id
            );
            assert!(
                op.output_schema.is_object(),
                "op {} missing output_schema",
                op.id
            );
        }
    }

    #[test]
    fn introspect_operations_have_ai_hints() {
        let intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        for op in &intro.operations {
            assert!(
                !op.ai_hints.when_to_use.is_empty(),
                "op {} missing when_to_use",
                op.id
            );
            assert!(
                !op.ai_hints.common_mistakes.is_empty(),
                "op {} missing common_mistakes",
                op.id
            );
        }
    }

    #[test]
    fn introspect_filter_comma_separated() {
        let intro =
            simulate_introspection("fcp.twitter:social:v1", Some("post_tweet,send_dm")).unwrap();
        assert_eq!(intro.operations.len(), 2);
    }

    #[test]
    fn introspect_filter_no_match() {
        let intro =
            simulate_introspection("fcp.twitter:social:v1", Some("nonexistent_op")).unwrap();
        assert!(intro.operations.is_empty());
    }

    #[test]
    fn introspect_has_resource_types() {
        let intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        assert_eq!(intro.resource_types.len(), 2);
        assert!(intro.resource_types.iter().any(|r| r.name == "Tweet"));
        assert!(intro.resource_types.iter().any(|r| r.name == "User"));
    }

    #[test]
    fn introspect_has_auth_caps() {
        let intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        let auth = intro.auth_caps.unwrap();
        assert!(auth.methods.contains(&"oauth2".to_string()));
        assert!(auth.supports_refresh);
    }

    #[test]
    fn introspect_event_caps() {
        let intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        let caps = intro.event_caps.unwrap();
        assert!(caps.streaming);
        assert!(caps.replay);
        assert_eq!(caps.min_buffer_events, 1000);
    }

    // ---- ConnectorHealthDisplay ----

    #[test]
    fn health_labels() {
        assert_eq!(ConnectorHealth::healthy().label(), "healthy");
        assert_eq!(ConnectorHealth::degraded("slow").label(), "degraded");
        assert_eq!(ConnectorHealth::unavailable("down").label(), "unavailable");
    }

    #[test]
    fn health_reason() {
        assert!(ConnectorHealth::healthy().reason().is_none());
        assert_eq!(ConnectorHealth::degraded("slow").reason(), Some("slow"));
        assert_eq!(
            ConnectorHealth::unavailable("crash").reason(),
            Some("crash")
        );
    }

    // ---- introspect_serialization_roundtrip ----

    #[test]
    fn info_json_serialization_roundtrip() {
        let info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: ConnectorInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, info.id);
        assert_eq!(deserialized.operations.len(), info.operations.len());
    }

    #[test]
    fn introspection_json_serialization_roundtrip() {
        let intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        let json = serde_json::to_string(&intro).unwrap();
        let deserialized: ConnectorIntrospection = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.connector_id, intro.connector_id);
        assert_eq!(deserialized.operations.len(), intro.operations.len());
    }

    // ── Pin/Unpin/Rollout/Rollback Tests ─────────────────────────

    #[test]
    fn pin_valid_semver() {
        let args = PinArgs {
            connector_id: "fcp.discord:messaging:v1".to_string(),
            version: "1.2.3".to_string(),
            json: true,
        };
        run_pin(&args).unwrap();
    }

    #[test]
    fn pin_invalid_semver_fails() {
        let args = PinArgs {
            connector_id: "fcp.discord:messaging:v1".to_string(),
            version: "not-a-version".to_string(),
            json: true,
        };
        assert!(run_pin(&args).is_err());
    }

    #[test]
    fn pin_prerelease_version() {
        let args = PinArgs {
            connector_id: "fcp.discord:messaging:v1".to_string(),
            version: "1.0.0-beta.1".to_string(),
            json: true,
        };
        run_pin(&args).unwrap();
    }

    #[test]
    fn pin_human_output() {
        let args = PinArgs {
            connector_id: "fcp.test:utility:v1".to_string(),
            version: "2.0.0".to_string(),
            json: false,
        };
        run_pin(&args).unwrap();
    }

    #[test]
    fn unpin_produces_output() {
        let args = UnpinArgs {
            connector_id: "fcp.discord:messaging:v1".to_string(),
            json: true,
        };
        run_unpin(&args).unwrap();
    }

    #[test]
    fn unpin_human_output() {
        let args = UnpinArgs {
            connector_id: "fcp.test:utility:v1".to_string(),
            json: false,
        };
        run_unpin(&args).unwrap();
    }

    #[test]
    fn rollout_set_valid() {
        let args = RolloutSetArgs {
            connector_id: "fcp.discord:messaging:v1".to_string(),
            canary: 25,
            json: true,
        };
        run_rollout_set(&args).unwrap();
    }

    #[test]
    fn rollout_set_zero_percent() {
        let args = RolloutSetArgs {
            connector_id: "fcp.discord:messaging:v1".to_string(),
            canary: 0,
            json: true,
        };
        run_rollout_set(&args).unwrap();
    }

    #[test]
    fn rollout_set_hundred_percent() {
        let args = RolloutSetArgs {
            connector_id: "fcp.discord:messaging:v1".to_string(),
            canary: 100,
            json: true,
        };
        run_rollout_set(&args).unwrap();
    }

    #[test]
    fn rollout_set_human_output() {
        let args = RolloutSetArgs {
            connector_id: "fcp.test:utility:v1".to_string(),
            canary: 50,
            json: false,
        };
        run_rollout_set(&args).unwrap();
    }

    #[test]
    fn rollout_status_json() {
        let args = RolloutStatusArgs {
            connector_id: "fcp.discord:messaging:v1".to_string(),
            json: true,
        };
        run_rollout_status(&args).unwrap();
    }

    #[test]
    fn rollout_status_human() {
        let args = RolloutStatusArgs {
            connector_id: "fcp.test:utility:v1".to_string(),
            json: false,
        };
        run_rollout_status(&args).unwrap();
    }

    #[test]
    fn rollback_valid_version() {
        let args = RollbackArgs {
            connector_id: "fcp.discord:messaging:v1".to_string(),
            to: "1.0.0".to_string(),
            json: true,
        };
        run_rollback(&args).unwrap();
    }

    #[test]
    fn rollback_invalid_version_fails() {
        let args = RollbackArgs {
            connector_id: "fcp.discord:messaging:v1".to_string(),
            to: "bad".to_string(),
            json: true,
        };
        assert!(run_rollback(&args).is_err());
    }

    #[test]
    fn rollback_human_output() {
        let args = RollbackArgs {
            connector_id: "fcp.test:utility:v1".to_string(),
            to: "0.9.0".to_string(),
            json: false,
        };
        run_rollback(&args).unwrap();
    }

    #[test]
    fn pin_output_json_has_expected_fields() {
        let output = PinOutput {
            connector_id: "fcp.test:utility:v1".to_string(),
            action: "pin".to_string(),
            version: Some("1.0.0".to_string()),
            message: "test".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"connector_id\""));
        assert!(json.contains("\"action\":\"pin\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
    }

    #[test]
    fn rollout_status_output_json_has_expected_fields() {
        let output = RolloutStatusOutput {
            connector_id: "fcp.test:utility:v1".to_string(),
            state: "canary".to_string(),
            version: "2.0.0".to_string(),
            canary_percent: 50,
            pinned: false,
            health: "healthy".to_string(),
            message: "test".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"state\":\"canary\""));
        assert!(json.contains("\"canary_percent\":50"));
        assert!(json.contains("\"pinned\":false"));
    }

    #[test]
    fn rollback_output_json_has_expected_fields() {
        let output = RollbackOutput {
            connector_id: "fcp.test:utility:v1".to_string(),
            from_version: "2.0.0".to_string(),
            to_version: "1.0.0".to_string(),
            message: "test".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"from_version\":\"2.0.0\""));
        assert!(json.contains("\"to_version\":\"1.0.0\""));
    }

    // ── Verify Tests ─────────────────────────────────────────────

    #[test]
    fn verify_output_serializes_to_json() {
        let output = VerifyOutput {
            connector_id: "fcp.test:utility:v1".to_string(),
            decision: "deny".to_string(),
            reason_code: "attestation_missing".to_string(),
            artifact_digest: String::new(),
            steps: vec![VerifyStepOutput {
                step: "attestation_presence".to_string(),
                passed: false,
                detail: "missing".to_string(),
            }],
            evidence_digest: "blake3-256:abcd".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: true,
                require_sbom: true,
                min_slsa_level: 0,
                allow_unsigned: false,
            },
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"decision\":\"deny\""));
        assert!(json.contains("\"reason_code\":\"attestation_missing\""));
        assert!(json.contains("\"require_attestation\":true"));
    }

    #[test]
    fn verify_policy_output_fields() {
        let output = VerifyPolicyOutput {
            require_attestation: false,
            require_sbom: false,
            min_slsa_level: 3,
            allow_unsigned: true,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"min_slsa_level\":3"));
        assert!(json.contains("\"allow_unsigned\":true"));
    }

    #[test]
    fn verify_step_output_serializes() {
        let step = VerifyStepOutput {
            step: "sbom_validation".to_string(),
            passed: true,
            detail: "SBOM structurally valid".to_string(),
        };
        let json = serde_json::to_string(&step).unwrap();
        assert!(json.contains("\"passed\":true"));
        assert!(json.contains("sbom_validation"));
    }

    #[test]
    fn verify_args_allow_unsigned_relaxes_policy() {
        // When allow_unsigned is set with no attestation/sbom paths,
        // the policy should not require them.
        let args = VerifyArgs {
            connector_id: "fcp.test:utility:v1".to_string(),
            attestation: None,
            sbom: None,
            digest: None,
            min_slsa_level: 0,
            allow_unsigned: true,
            json: true,
        };
        // Note: run_verify exits process on failure, so we test indirectly
        // via the policy construction logic.
        let policy = SupplyChainVerificationPolicy {
            require_attestation: args.attestation.is_some() || !args.allow_unsigned,
            require_sbom: args.sbom.is_some() || !args.allow_unsigned,
            min_slsa_level: args.min_slsa_level,
            trusted_builders: vec![],
            allow_unsigned: args.allow_unsigned,
            require_digest_match: args.digest.is_some(),
        };
        assert!(!policy.require_attestation);
        assert!(!policy.require_sbom);
        assert!(policy.allow_unsigned);
    }

    #[test]
    fn verify_args_strict_requires_attestation() {
        let args = VerifyArgs {
            connector_id: "fcp.test:utility:v1".to_string(),
            attestation: None,
            sbom: None,
            digest: None,
            min_slsa_level: 0,
            allow_unsigned: false,
            json: true,
        };
        let policy = SupplyChainVerificationPolicy {
            require_attestation: args.attestation.is_some() || !args.allow_unsigned,
            require_sbom: args.sbom.is_some() || !args.allow_unsigned,
            min_slsa_level: args.min_slsa_level,
            trusted_builders: vec![],
            allow_unsigned: args.allow_unsigned,
            require_digest_match: args.digest.is_some(),
        };
        assert!(policy.require_attestation);
        assert!(policy.require_sbom);
        assert!(!policy.allow_unsigned);
    }

    #[test]
    fn verify_args_with_attestation_path_requires_it() {
        let args = VerifyArgs {
            connector_id: "fcp.test:utility:v1".to_string(),
            attestation: Some("/tmp/att.json".to_string()),
            sbom: None,
            digest: None,
            min_slsa_level: 2,
            allow_unsigned: true,
            json: true,
        };
        let policy = SupplyChainVerificationPolicy {
            require_attestation: args.attestation.is_some() || !args.allow_unsigned,
            require_sbom: args.sbom.is_some() || !args.allow_unsigned,
            min_slsa_level: args.min_slsa_level,
            trusted_builders: vec![],
            allow_unsigned: args.allow_unsigned,
            require_digest_match: args.digest.is_some(),
        };
        assert!(policy.require_attestation);
        assert!(!policy.require_sbom);
        assert_eq!(policy.min_slsa_level, 2);
    }
}
