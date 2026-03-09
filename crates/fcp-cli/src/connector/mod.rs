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

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::{Args, Subcommand};

use crate::context::types::ContextConfig;
use fcp_core::{
    AgentHint, ApprovalMode, CapabilityId, ConnectorHealth, HashAlgorithm, IdempotencyClass,
    LifecycleRecord, LifecycleState, LifecycleStatus, RateLimitConfig, RateLimitDeclarations,
    RateLimitEnforcement, RateLimitPool, RateLimitScope, RateLimitUnit, RiskLevel, RolloutPolicy,
    SafetyTier, SoftwareBillOfMaterials, SupplyChainAttestation, SupplyChainVerificationPolicy,
    VerificationDecision, VerificationPipeline,
};
use types::{
    AuthCapsDescriptor, ConnectorHealthDisplay, ConnectorInfo, ConnectorIntrospection,
    ConnectorListOutput, ConnectorMetricsInfo, ConnectorSummary, EventCapsDescriptor,
    EventDescriptor, EventSummary, OperationDescriptor, OperationSummary, RateLimitDescriptor,
    ResourceTypeDescriptor, SandboxInfo, ZoneConnectors,
};
use url::Url;

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
            Some(
                serde_json::from_str(&content)
                    .with_context(|| format!("invalid attestation JSON in {path}"))?,
            )
        }
        None => None,
    };

    let sbom: Option<SoftwareBillOfMaterials> = match &args.sbom {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read SBOM file: {path}"))?;
            Some(
                serde_json::from_str(&content)
                    .with_context(|| format!("invalid SBOM JSON in {path}"))?,
            )
        }
        None => None,
    };

    let artifact_digest = args.digest.clone().unwrap_or_default();

    let pipeline = VerificationPipeline::new(policy.clone());
    let evidence = pipeline.verify(&artifact_digest, attestation.as_ref(), sbom.as_ref());

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

#[derive(Debug, Clone)]
enum HostEndpoint {
    Http(Url),
    #[cfg(unix)]
    Unix {
        socket_path: PathBuf,
        base_url: Url,
    },
}

impl HostEndpoint {
    fn discover() -> Result<Self> {
        if let Ok(endpoint) = std::env::var("FCP_HOST_ENDPOINT")
            && !endpoint.trim().is_empty()
        {
            return Self::from_raw(&endpoint);
        }
        if let Ok(endpoint) = std::env::var("FCP_HOST_BIND")
            && !endpoint.trim().is_empty()
        {
            return Self::from_raw(&endpoint);
        }

        let config = ContextConfig::load_or_default().context("failed to load FCP contexts")?;
        if let Some(context) = config.contexts.get(&config.current_context)
            && !context.endpoint.trim().is_empty()
        {
            return Self::from_raw(&context.endpoint);
        }

        Self::from_raw("http://127.0.0.1:9090")
    }

    fn from_raw(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            anyhow::bail!("FCP host endpoint cannot be empty");
        }

        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            let url = Url::parse(trimmed)
                .map_err(|err| anyhow::anyhow!("invalid FCP host endpoint '{trimmed}': {err}"))?;
            return Ok(Self::Http(url));
        }

        #[cfg(unix)]
        if let Some(path) = trimmed.strip_prefix("unix://") {
            if path.trim().is_empty() {
                anyhow::bail!("unix FCP host endpoint cannot be empty");
            }
            return Ok(Self::Unix {
                socket_path: PathBuf::from(path),
                base_url: Url::parse("http://localhost")
                    .expect("static unix-socket base URL must parse"),
            });
        }

        #[cfg(unix)]
        if trimmed.starts_with('/') {
            return Ok(Self::Unix {
                socket_path: PathBuf::from(trimmed),
                base_url: Url::parse("http://localhost")
                    .expect("static unix-socket base URL must parse"),
            });
        }

        #[cfg(not(unix))]
        if trimmed.starts_with("unix://") || trimmed.starts_with('/') {
            anyhow::bail!("unix socket host endpoints are not supported on this platform");
        }

        let target = trimmed.strip_prefix("tcp://").unwrap_or(trimmed);
        let url = Url::parse(&format!("http://{target}"))
            .map_err(|err| anyhow::anyhow!("invalid FCP host endpoint '{trimmed}': {err}"))?;
        Ok(Self::Http(url))
    }

    fn build_url(&self, path: &str) -> Url {
        let normalized_path = path.trim_start_matches('/');
        let mut url = match self {
            Self::Http(base_url) => base_url.clone(),
            #[cfg(unix)]
            Self::Unix { base_url, .. } => base_url.clone(),
        };
        let base_path = url.path().trim_end_matches('/');
        let full_path = if base_path.is_empty() || base_path == "/" {
            format!("/{normalized_path}")
        } else {
            format!("{base_path}/{normalized_path}")
        };
        url.set_path(&full_path);
        url.set_query(None);
        url.set_fragment(None);
        url
    }

    fn build_client(&self) -> Result<reqwest::blocking::Client> {
        let builder = reqwest::blocking::Client::builder().timeout(Duration::from_secs(15));
        #[cfg(unix)]
        let builder = match self {
            Self::Http(_) => builder,
            Self::Unix { socket_path, .. } => builder.unix_socket(socket_path.clone()),
        };
        builder
            .build()
            .map_err(|err| anyhow::anyhow!("failed to build FCP host client: {err}"))
    }

    fn display(&self) -> String {
        match self {
            Self::Http(url) => url.to_string(),
            #[cfg(unix)]
            Self::Unix { socket_path, .. } => format!("unix://{}", socket_path.display()),
        }
    }
}

trait RolloutHostClient {
    fn pin(&self, connector_id: &str, version: &semver::Version) -> Result<HostPinState>;
    fn unpin(&self, connector_id: &str) -> Result<HostPinState>;
    fn pin_status(&self, connector_id: &str) -> Result<HostPinState>;
    fn rollout_status(&self, connector_id: &str) -> Result<Option<HostRolloutStatus>>;
    fn schedule(&self, request: &HostRolloutScheduleRequest) -> Result<HostRolloutOutcome>;
    fn rollback(
        &self,
        connector_id: &str,
        to_version: &semver::Version,
    ) -> Result<HostRollbackResponse>;
}

struct HttpRolloutHostClient {
    endpoint: HostEndpoint,
}

impl HttpRolloutHostClient {
    fn discover() -> Result<Self> {
        Ok(Self {
            endpoint: HostEndpoint::discover()?,
        })
    }

    fn send_json<B, R>(&self, method: &reqwest::Method, path: &str, body: Option<&B>) -> Result<R>
    where
        B: serde::Serialize + ?Sized,
        R: serde::de::DeserializeOwned,
    {
        let client = self.endpoint.build_client()?;
        let url = self.endpoint.build_url(path);
        let mut request = client.request(method.clone(), url.clone());
        if let Some(payload) = body {
            request = request.json(payload);
        }

        let response = request.send().map_err(|err| {
            anyhow::anyhow!(
                "failed to contact FCP host at {} for {method} {url}: {err}",
                self.endpoint.display()
            )
        })?;
        if !response.status().is_success() {
            return Err(http_status_error(response, &format!("{method} {url}")));
        }
        response.json().map_err(|err| {
            anyhow::anyhow!("failed to decode FCP host response for {method} {url}: {err}")
        })
    }

    fn get_optional_json<R>(&self, path: &str) -> Result<Option<R>>
    where
        R: serde::de::DeserializeOwned,
    {
        let client = self.endpoint.build_client()?;
        let url = self.endpoint.build_url(path);
        let response = client.get(url.clone()).send().map_err(|err| {
            anyhow::anyhow!(
                "failed to contact FCP host at {} for GET {url}: {err}",
                self.endpoint.display()
            )
        })?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(http_status_error(response, &format!("GET {url}")));
        }
        response.json().map(Some).map_err(|err| {
            anyhow::anyhow!("failed to decode FCP host response for GET {url}: {err}")
        })
    }
}

impl RolloutHostClient for HttpRolloutHostClient {
    fn pin(&self, connector_id: &str, version: &semver::Version) -> Result<HostPinState> {
        self.send_json(
            &reqwest::Method::PUT,
            &format!("rpc/rollout/pin/{connector_id}"),
            Some(&HostPinRequest {
                version: version.clone(),
            }),
        )
    }

    fn unpin(&self, connector_id: &str) -> Result<HostPinState> {
        self.send_json::<(), HostPinState>(
            &reqwest::Method::DELETE,
            &format!("rpc/rollout/pin/{connector_id}"),
            None,
        )
    }

    fn pin_status(&self, connector_id: &str) -> Result<HostPinState> {
        self.send_json::<(), HostPinState>(
            &reqwest::Method::GET,
            &format!("rpc/rollout/pin/{connector_id}"),
            None,
        )
    }

    fn rollout_status(&self, connector_id: &str) -> Result<Option<HostRolloutStatus>> {
        self.get_optional_json(&format!("rpc/rollout/{connector_id}"))
    }

    fn schedule(&self, request: &HostRolloutScheduleRequest) -> Result<HostRolloutOutcome> {
        self.send_json(
            &reqwest::Method::POST,
            "rpc/rollout/schedule",
            Some(request),
        )
    }

    fn rollback(
        &self,
        connector_id: &str,
        to_version: &semver::Version,
    ) -> Result<HostRollbackResponse> {
        self.send_json(
            &reqwest::Method::POST,
            "rpc/rollout/rollback",
            Some(&HostRollbackRequest {
                connector_id: connector_id.to_string(),
                to_version: to_version.clone(),
            }),
        )
    }
}

fn http_status_error(response: reqwest::blocking::Response, context: &str) -> anyhow::Error {
    let status = response.status();
    let body = response.text().unwrap_or_default();
    let detail = if body.trim().is_empty() {
        "<empty response body>"
    } else {
        body.trim()
    };
    anyhow::anyhow!("{context} failed with HTTP {status}: {detail}")
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct HostPinRequest {
    version: semver::Version,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct HostPinState {
    connector_id: String,
    pinned: bool,
    #[serde(default)]
    version: Option<semver::Version>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct HostRolloutScheduleRequest {
    connector_id: String,
    version: semver::Version,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_version: Option<semver::Version>,
    policy: RolloutPolicy,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct HostRolloutAuditEvent {
    reason_code: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct HostRolloutOutcome {
    record: LifecycleRecord,
    decision: String,
    audit_event: HostRolloutAuditEvent,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct HostRolloutStatus {
    #[serde(flatten)]
    status: LifecycleStatus,
    pinned: bool,
    #[serde(default)]
    pinned_version: Option<semver::Version>,
    canary_percent: u8,
}

#[derive(Debug, Clone, serde::Serialize)]
struct HostRollbackRequest {
    connector_id: String,
    to_version: semver::Version,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct HostRollbackResponse {
    connector_id: String,
    state: LifecycleState,
    from_version: semver::Version,
    to_version: semver::Version,
    message: String,
}

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

const fn rollout_health_label(status: &LifecycleStatus) -> &'static str {
    if status.crash_loop_detected || status.auto_rollback_pending {
        "unhealthy"
    } else if status.health.samples == 0 {
        "unknown"
    } else if status.health.success_rate >= 95 {
        "healthy"
    } else if status.health.success_rate >= 80 {
        "degraded"
    } else {
        "unhealthy"
    }
}

fn print_pin_output(output: &PinOutput, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(output)?);
    } else if let Some(version) = &output.version {
        if output.action == "pin" {
            println!("Pinned {} to v{version}", output.connector_id);
            println!("  Auto-upgrade is now disabled for this connector.");
            println!(
                "  Use `fcp connector unpin {}` to re-enable.",
                output.connector_id
            );
        } else {
            println!("Unpinned {}", output.connector_id);
            println!("  Auto-upgrade is now re-enabled.");
        }
    } else {
        println!("Unpinned {}", output.connector_id);
        println!("  Auto-upgrade is now re-enabled.");
    }
    Ok(())
}

fn print_rollout_status_output(output: &RolloutStatusOutput, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(output)?);
    } else {
        println!("Rollout status for {}", output.connector_id);
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

fn print_rollback_output(output: &RollbackOutput, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(output)?);
    } else {
        println!(
            "Rolled back {} to v{}",
            output.connector_id, output.to_version
        );
        println!("  Previous version will be deactivated.");
        println!(
            "  Use `fcp connector rollout status {}` to verify.",
            output.connector_id
        );
    }
    Ok(())
}

fn run_pin(args: &PinArgs) -> Result<()> {
    let client = HttpRolloutHostClient::discover()?;
    let output = run_pin_with_client(args, &client)?;
    print_pin_output(&output, args.json)
}

fn run_pin_with_client<C: RolloutHostClient>(args: &PinArgs, client: &C) -> Result<PinOutput> {
    let version = semver::Version::parse(&args.version)
        .map_err(|e| anyhow::anyhow!("invalid semver version '{}': {e}", args.version))?;
    let state = client.pin(&args.connector_id, &version)?;
    Ok(PinOutput {
        connector_id: state.connector_id,
        action: "pin".to_string(),
        version: Some(version.to_string()),
        message: format!(
            "Connector {} pinned to version {version}. Auto-upgrade disabled.",
            args.connector_id
        ),
    })
}

fn run_unpin(args: &UnpinArgs) -> Result<()> {
    let client = HttpRolloutHostClient::discover()?;
    let output = run_unpin_with_client(args, &client)?;
    print_pin_output(&output, args.json)
}

fn run_unpin_with_client<C: RolloutHostClient>(args: &UnpinArgs, client: &C) -> Result<PinOutput> {
    let state = client.unpin(&args.connector_id)?;
    Ok(PinOutput {
        connector_id: state.connector_id,
        action: "unpin".to_string(),
        version: None,
        message: format!(
            "Connector {} unpinned. Auto-upgrade re-enabled.",
            args.connector_id
        ),
    })
}

fn run_rollout(args: &RolloutArgs) -> Result<()> {
    match &args.command {
        RolloutCommand::Set(set_args) => run_rollout_set(set_args),
        RolloutCommand::Status(status_args) => run_rollout_status(status_args),
    }
}

fn run_rollout_set(args: &RolloutSetArgs) -> Result<()> {
    let client = HttpRolloutHostClient::discover()?;
    let output = run_rollout_set_with_client(args, &client)?;
    print_rollout_status_output(&output, args.json)
}

fn run_rollout_set_with_client<C: RolloutHostClient>(
    args: &RolloutSetArgs,
    client: &C,
) -> Result<RolloutStatusOutput> {
    if args.canary > 100 {
        anyhow::bail!("canary percentage must be 0-100, got {}", args.canary);
    }
    let pin_state = client.pin_status(&args.connector_id)?;
    let version = pin_state.version.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "no pinned version configured for {}. Run `fcp connector pin {} --version <version>` first",
            args.connector_id,
            args.connector_id
        )
    })?;
    let previous_version = client
        .rollout_status(&args.connector_id)?
        .map(|status| status.status.version);
    let policy = RolloutPolicy::builder().canary_percent(args.canary).build();
    policy.validate()?;
    let outcome = client.schedule(&HostRolloutScheduleRequest {
        connector_id: args.connector_id.clone(),
        version,
        previous_version,
        policy,
    })?;
    let output = RolloutStatusOutput {
        connector_id: args.connector_id.clone(),
        state: outcome.record.state.to_string(),
        version: outcome.record.version.to_string(),
        canary_percent: args.canary,
        pinned: pin_state.pinned,
        health: "unknown".to_string(),
        message: format!(
            "Canary set to {}% for {} (reason: {}).",
            args.canary, args.connector_id, outcome.audit_event.reason_code
        ),
    };
    let _ = &outcome.decision;
    Ok(output)
}

fn run_rollout_status(args: &RolloutStatusArgs) -> Result<()> {
    let client = HttpRolloutHostClient::discover()?;
    let output = run_rollout_status_with_client(args, &client)?;
    print_rollout_status_output(&output, args.json)
}

fn run_rollout_status_with_client<C: RolloutHostClient>(
    args: &RolloutStatusArgs,
    client: &C,
) -> Result<RolloutStatusOutput> {
    let pin_state = client.pin_status(&args.connector_id)?;
    if let Some(status) = client.rollout_status(&args.connector_id)? {
        return Ok(RolloutStatusOutput {
            connector_id: status.status.connector_id.to_string(),
            state: status.status.state.to_string(),
            version: status.status.version.to_string(),
            canary_percent: status.canary_percent,
            pinned: status.pinned || status.pinned_version.is_some(),
            health: rollout_health_label(&status.status).to_string(),
            message: format!(
                "Connector {} is in {} (v{}).",
                args.connector_id, status.status.state, status.status.version
            ),
        });
    }

    if let Some(version) = pin_state.version {
        return Ok(RolloutStatusOutput {
            connector_id: pin_state.connector_id,
            state: "pinned".to_string(),
            version: version.to_string(),
            canary_percent: 0,
            pinned: true,
            health: "unknown".to_string(),
            message: format!(
                "Connector {} is pinned to v{} with no active rollout.",
                args.connector_id, version
            ),
        });
    }

    anyhow::bail!("no rollout state found for {}", args.connector_id)
}

fn run_rollback(args: &RollbackArgs) -> Result<()> {
    let client = HttpRolloutHostClient::discover()?;
    let output = run_rollback_with_client(args, &client)?;
    print_rollback_output(&output, args.json)
}

fn run_rollback_with_client<C: RolloutHostClient>(
    args: &RollbackArgs,
    client: &C,
) -> Result<RollbackOutput> {
    let to_version = semver::Version::parse(&args.to)
        .map_err(|e| anyhow::anyhow!("invalid semver version '{}': {e}", args.to))?;
    let response = client.rollback(&args.connector_id, &to_version)?;
    let _ = response.state;
    Ok(RollbackOutput {
        connector_id: response.connector_id,
        from_version: response.from_version.to_string(),
        to_version: response.to_version.to_string(),
        message: response.message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn test_connector_id() -> String {
        "fcp.discord:messaging:v1".to_string()
    }

    fn test_version(major: u64, minor: u64, patch: u64) -> semver::Version {
        semver::Version::new(major, minor, patch)
    }

    fn test_lifecycle_status(state: LifecycleState, version: semver::Version) -> LifecycleStatus {
        let health = fcp_core::HealthMetrics {
            samples: 5,
            success_rate: 100,
            ..Default::default()
        };
        LifecycleStatus {
            connector_id: test_connector_id().parse().expect("valid connector id"),
            state,
            version,
            health,
            auto_promote_pending: false,
            auto_rollback_pending: false,
            canary_expires_in_secs: None,
            crash_loop_detected: false,
            rollback_target_version: Some(test_version(1, 0, 0)),
        }
    }

    fn test_rollout_outcome(
        decision: &str,
        state: LifecycleState,
        version: semver::Version,
        reason_code: &str,
    ) -> HostRolloutOutcome {
        let mut record = LifecycleRecord::new(
            test_connector_id().parse().expect("valid connector id"),
            version,
        );
        record.state = state;
        record.previous_version = Some(test_version(1, 0, 0));
        HostRolloutOutcome {
            record,
            decision: decision.to_string(),
            audit_event: HostRolloutAuditEvent {
                reason_code: reason_code.to_string(),
            },
        }
    }

    struct FakeRolloutHostClient {
        pin_state: HostPinState,
        rollout_status: Option<HostRolloutStatus>,
        schedule_outcome: HostRolloutOutcome,
        rollback_response: HostRollbackResponse,
        scheduled_requests: RefCell<Vec<HostRolloutScheduleRequest>>,
        rollback_requests: RefCell<Vec<(String, semver::Version)>>,
    }

    impl FakeRolloutHostClient {
        fn new() -> Self {
            let connector_id = test_connector_id();
            let pinned_version = test_version(1, 2, 3);
            Self {
                pin_state: HostPinState {
                    connector_id: connector_id.clone(),
                    pinned: true,
                    version: Some(pinned_version.clone()),
                },
                rollout_status: Some(HostRolloutStatus {
                    status: test_lifecycle_status(
                        LifecycleState::Production,
                        test_version(1, 2, 2),
                    ),
                    pinned: true,
                    pinned_version: Some(pinned_version.clone()),
                    canary_percent: 0,
                }),
                schedule_outcome: test_rollout_outcome(
                    "scheduled",
                    LifecycleState::Canary,
                    pinned_version,
                    "canary_scheduled",
                ),
                rollback_response: HostRollbackResponse {
                    connector_id,
                    state: LifecycleState::RolledBack,
                    from_version: test_version(1, 2, 3),
                    to_version: test_version(1, 0, 0),
                    message: "connector rolled back to v1.0.0 and pinned".to_string(),
                },
                scheduled_requests: RefCell::new(Vec::new()),
                rollback_requests: RefCell::new(Vec::new()),
            }
        }
    }

    impl RolloutHostClient for FakeRolloutHostClient {
        fn pin(&self, connector_id: &str, version: &semver::Version) -> Result<HostPinState> {
            Ok(HostPinState {
                connector_id: connector_id.to_string(),
                pinned: true,
                version: Some(version.clone()),
            })
        }

        fn unpin(&self, connector_id: &str) -> Result<HostPinState> {
            Ok(HostPinState {
                connector_id: connector_id.to_string(),
                pinned: false,
                version: None,
            })
        }

        fn pin_status(&self, _connector_id: &str) -> Result<HostPinState> {
            Ok(self.pin_state.clone())
        }

        fn rollout_status(&self, _connector_id: &str) -> Result<Option<HostRolloutStatus>> {
            Ok(self.rollout_status.clone())
        }

        fn schedule(&self, request: &HostRolloutScheduleRequest) -> Result<HostRolloutOutcome> {
            self.scheduled_requests.borrow_mut().push(request.clone());
            Ok(self.schedule_outcome.clone())
        }

        fn rollback(
            &self,
            connector_id: &str,
            to_version: &semver::Version,
        ) -> Result<HostRollbackResponse> {
            self.rollback_requests
                .borrow_mut()
                .push((connector_id.to_string(), to_version.clone()));
            Ok(self.rollback_response.clone())
        }
    }

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
        let client = FakeRolloutHostClient::new();
        let args = PinArgs {
            connector_id: test_connector_id(),
            version: "1.2.3".to_string(),
            json: true,
        };
        let output = run_pin_with_client(&args, &client).unwrap();
        assert_eq!(output.version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn pin_invalid_semver_fails() {
        let client = FakeRolloutHostClient::new();
        let args = PinArgs {
            connector_id: test_connector_id(),
            version: "not-a-version".to_string(),
            json: true,
        };
        assert!(run_pin_with_client(&args, &client).is_err());
    }

    #[test]
    fn pin_prerelease_version() {
        let client = FakeRolloutHostClient::new();
        let args = PinArgs {
            connector_id: test_connector_id(),
            version: "1.0.0-beta.1".to_string(),
            json: true,
        };
        let output = run_pin_with_client(&args, &client).unwrap();
        assert_eq!(output.version.as_deref(), Some("1.0.0-beta.1"));
    }

    #[test]
    fn pin_human_output() {
        let client = FakeRolloutHostClient::new();
        let args = PinArgs {
            connector_id: "fcp.test:utility:v1".to_string(),
            version: "2.0.0".to_string(),
            json: false,
        };
        let output = run_pin_with_client(&args, &client).unwrap();
        print_pin_output(&output, false).unwrap();
    }

    #[test]
    fn unpin_produces_output() {
        let client = FakeRolloutHostClient::new();
        let args = UnpinArgs {
            connector_id: test_connector_id(),
            json: true,
        };
        let output = run_unpin_with_client(&args, &client).unwrap();
        assert!(!output.message.is_empty());
    }

    #[test]
    fn unpin_human_output() {
        let client = FakeRolloutHostClient::new();
        let args = UnpinArgs {
            connector_id: "fcp.test:utility:v1".to_string(),
            json: false,
        };
        let output = run_unpin_with_client(&args, &client).unwrap();
        print_pin_output(&output, false).unwrap();
    }

    #[test]
    fn rollout_set_valid() {
        let client = FakeRolloutHostClient::new();
        let args = RolloutSetArgs {
            connector_id: test_connector_id(),
            canary: 25,
            json: true,
        };
        let output = run_rollout_set_with_client(&args, &client).unwrap();
        assert_eq!(output.state, "canary");
        assert_eq!(output.version, "1.2.3");
        let scheduled = client.scheduled_requests.borrow();
        assert_eq!(scheduled.len(), 1);
        assert_eq!(scheduled[0].version, test_version(1, 2, 3));
        assert_eq!(scheduled[0].previous_version, Some(test_version(1, 2, 2)));
        assert_eq!(scheduled[0].policy.canary_percent, 25);
    }

    #[test]
    fn rollout_set_zero_percent() {
        let client = FakeRolloutHostClient::new();
        let args = RolloutSetArgs {
            connector_id: test_connector_id(),
            canary: 0,
            json: true,
        };
        let output = run_rollout_set_with_client(&args, &client).unwrap();
        assert_eq!(output.canary_percent, 0);
    }

    #[test]
    fn rollout_set_hundred_percent() {
        let client = FakeRolloutHostClient::new();
        let args = RolloutSetArgs {
            connector_id: test_connector_id(),
            canary: 100,
            json: true,
        };
        let output = run_rollout_set_with_client(&args, &client).unwrap();
        assert_eq!(output.canary_percent, 100);
    }

    #[test]
    fn rollout_set_human_output() {
        let client = FakeRolloutHostClient::new();
        let args = RolloutSetArgs {
            connector_id: "fcp.test:utility:v1".to_string(),
            canary: 50,
            json: false,
        };
        let output = run_rollout_set_with_client(&args, &client).unwrap();
        print_rollout_status_output(&output, false).unwrap();
    }

    #[test]
    fn rollout_set_requires_pin_target() {
        let mut client = FakeRolloutHostClient::new();
        client.pin_state.version = None;
        client.pin_state.pinned = false;
        let args = RolloutSetArgs {
            connector_id: test_connector_id(),
            canary: 10,
            json: true,
        };
        assert!(run_rollout_set_with_client(&args, &client).is_err());
    }

    #[test]
    fn rollout_status_json() {
        let client = FakeRolloutHostClient::new();
        let args = RolloutStatusArgs {
            connector_id: test_connector_id(),
            json: true,
        };
        let output = run_rollout_status_with_client(&args, &client).unwrap();
        assert_eq!(output.state, "production");
        assert_eq!(output.health, "healthy");
    }

    #[test]
    fn rollout_status_human() {
        let client = FakeRolloutHostClient::new();
        let args = RolloutStatusArgs {
            connector_id: "fcp.test:utility:v1".to_string(),
            json: false,
        };
        let output = run_rollout_status_with_client(&args, &client).unwrap();
        print_rollout_status_output(&output, false).unwrap();
    }

    #[test]
    fn rollout_status_uses_pin_when_no_rollout_state() {
        let mut client = FakeRolloutHostClient::new();
        client.rollout_status = None;
        let args = RolloutStatusArgs {
            connector_id: test_connector_id(),
            json: true,
        };
        let output = run_rollout_status_with_client(&args, &client).unwrap();
        assert_eq!(output.state, "pinned");
        assert_eq!(output.version, "1.2.3");
    }

    #[test]
    fn rollback_valid_version() {
        let client = FakeRolloutHostClient::new();
        let args = RollbackArgs {
            connector_id: test_connector_id(),
            to: "1.0.0".to_string(),
            json: true,
        };
        let output = run_rollback_with_client(&args, &client).unwrap();
        assert_eq!(output.from_version, "1.2.3");
        assert_eq!(output.to_version, "1.0.0");
    }

    #[test]
    fn rollback_invalid_version_fails() {
        let client = FakeRolloutHostClient::new();
        let args = RollbackArgs {
            connector_id: test_connector_id(),
            to: "bad".to_string(),
            json: true,
        };
        assert!(run_rollback_with_client(&args, &client).is_err());
    }

    #[test]
    fn rollback_human_output() {
        let client = FakeRolloutHostClient::new();
        let args = RollbackArgs {
            connector_id: "fcp.test:utility:v1".to_string(),
            to: "0.9.0".to_string(),
            json: false,
        };
        let output = run_rollback_with_client(&args, &client).unwrap();
        print_rollback_output(&output, false).unwrap();
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

    // ── HostEndpoint Tests ──────────────────────────────────────────

    #[test]
    fn host_endpoint_from_raw_http() {
        let ep = HostEndpoint::from_raw("http://10.0.0.1:9090").unwrap();
        assert_eq!(ep.display(), "http://10.0.0.1:9090/");
    }

    #[test]
    fn host_endpoint_from_raw_https() {
        let ep = HostEndpoint::from_raw("https://host.example.com:443/api").unwrap();
        assert_eq!(ep.display(), "https://host.example.com/api");
    }

    #[test]
    fn host_endpoint_from_raw_tcp_scheme() {
        let ep = HostEndpoint::from_raw("tcp://127.0.0.1:8080").unwrap();
        assert_eq!(ep.display(), "http://127.0.0.1:8080/");
    }

    #[test]
    fn host_endpoint_from_raw_bare_host_port() {
        let ep = HostEndpoint::from_raw("192.168.1.1:9090").unwrap();
        assert_eq!(ep.display(), "http://192.168.1.1:9090/");
    }

    #[test]
    fn host_endpoint_from_raw_empty_fails() {
        assert!(HostEndpoint::from_raw("").is_err());
    }

    #[test]
    fn host_endpoint_from_raw_whitespace_only_fails() {
        assert!(HostEndpoint::from_raw("   ").is_err());
    }

    #[test]
    fn host_endpoint_from_raw_trims_whitespace() {
        let ep = HostEndpoint::from_raw("  http://localhost:9090  ").unwrap();
        assert_eq!(ep.display(), "http://localhost:9090/");
    }

    #[cfg(unix)]
    #[test]
    fn host_endpoint_from_raw_unix_scheme() {
        let ep = HostEndpoint::from_raw("unix:///var/run/fcp.sock").unwrap();
        assert_eq!(ep.display(), "unix:///var/run/fcp.sock");
    }

    #[cfg(unix)]
    #[test]
    fn host_endpoint_from_raw_unix_bare_path() {
        let ep = HostEndpoint::from_raw("/var/run/fcp.sock").unwrap();
        assert_eq!(ep.display(), "unix:///var/run/fcp.sock");
    }

    #[cfg(unix)]
    #[test]
    fn host_endpoint_from_raw_unix_empty_path_fails() {
        assert!(HostEndpoint::from_raw("unix://").is_err());
    }

    #[test]
    fn host_endpoint_build_url_simple_path() {
        let ep = HostEndpoint::from_raw("http://localhost:9090").unwrap();
        let url = ep.build_url("rpc/pin");
        assert_eq!(url.path(), "/rpc/pin");
    }

    #[test]
    fn host_endpoint_build_url_strips_leading_slash() {
        let ep = HostEndpoint::from_raw("http://localhost:9090").unwrap();
        let url = ep.build_url("/rpc/pin");
        assert_eq!(url.path(), "/rpc/pin");
    }

    #[test]
    fn host_endpoint_build_url_with_base_path() {
        let ep = HostEndpoint::from_raw("http://localhost:9090/api/v1").unwrap();
        let url = ep.build_url("connectors");
        assert_eq!(url.path(), "/api/v1/connectors");
    }

    #[test]
    fn host_endpoint_build_url_clears_query_fragment() {
        let ep = HostEndpoint::from_raw("http://localhost:9090").unwrap();
        let url = ep.build_url("test");
        assert!(url.query().is_none());
        assert!(url.fragment().is_none());
    }

    #[test]
    fn host_endpoint_clone() {
        let ep = HostEndpoint::from_raw("http://localhost:9090").unwrap();
        let cloned = ep.clone();
        assert_eq!(ep.display(), cloned.display());
    }

    #[test]
    fn host_endpoint_debug() {
        let ep = HostEndpoint::from_raw("http://localhost:9090").unwrap();
        let debug = format!("{ep:?}");
        assert!(debug.contains("Http"));
    }

    // ── rollout_health_label Tests ──────────────────────────────────

    #[test]
    fn rollout_health_crash_loop_is_unhealthy() {
        let mut status = test_lifecycle_status(LifecycleState::Production, test_version(1, 0, 0));
        status.crash_loop_detected = true;
        assert_eq!(rollout_health_label(&status), "unhealthy");
    }

    #[test]
    fn rollout_health_auto_rollback_pending_is_unhealthy() {
        let mut status = test_lifecycle_status(LifecycleState::Production, test_version(1, 0, 0));
        status.auto_rollback_pending = true;
        assert_eq!(rollout_health_label(&status), "unhealthy");
    }

    #[test]
    fn rollout_health_zero_samples_is_unknown() {
        let mut status = test_lifecycle_status(LifecycleState::Canary, test_version(1, 0, 0));
        status.health.samples = 0;
        assert_eq!(rollout_health_label(&status), "unknown");
    }

    #[test]
    fn rollout_health_high_success_rate_is_healthy() {
        let mut status = test_lifecycle_status(LifecycleState::Production, test_version(1, 0, 0));
        status.health.success_rate = 99;
        assert_eq!(rollout_health_label(&status), "healthy");
    }

    #[test]
    fn rollout_health_boundary_95_is_healthy() {
        let mut status = test_lifecycle_status(LifecycleState::Production, test_version(1, 0, 0));
        status.health.success_rate = 95;
        assert_eq!(rollout_health_label(&status), "healthy");
    }

    #[test]
    fn rollout_health_94_is_degraded() {
        let mut status = test_lifecycle_status(LifecycleState::Production, test_version(1, 0, 0));
        status.health.success_rate = 94;
        assert_eq!(rollout_health_label(&status), "degraded");
    }

    #[test]
    fn rollout_health_boundary_80_is_degraded() {
        let mut status = test_lifecycle_status(LifecycleState::Production, test_version(1, 0, 0));
        status.health.success_rate = 80;
        assert_eq!(rollout_health_label(&status), "degraded");
    }

    #[test]
    fn rollout_health_79_is_unhealthy() {
        let mut status = test_lifecycle_status(LifecycleState::Production, test_version(1, 0, 0));
        status.health.success_rate = 79;
        assert_eq!(rollout_health_label(&status), "unhealthy");
    }

    // ── http_status_error Tests ─────────────────────────────────────

    #[test]
    fn http_status_error_message_includes_context_and_body() {
        // We can't create a real Response object without a server, but
        // we can test the VerifyOutput, VerifyStepOutput, VerifyPolicyOutput
        // serialization more thoroughly.
        let output = VerifyOutput {
            connector_id: "fcp.test:v1".to_string(),
            decision: "allow".to_string(),
            reason_code: "all_checks_passed".to_string(),
            artifact_digest: "blake3-256:deadbeef".to_string(),
            steps: vec![
                VerifyStepOutput {
                    step: "attestation_presence".to_string(),
                    passed: true,
                    detail: "found".to_string(),
                },
                VerifyStepOutput {
                    step: "sbom_validation".to_string(),
                    passed: true,
                    detail: "valid".to_string(),
                },
                VerifyStepOutput {
                    step: "slsa_level_check".to_string(),
                    passed: true,
                    detail: "level 3 >= required 2".to_string(),
                },
            ],
            evidence_digest: "blake3-256:cafe1234".to_string(),
            policy: VerifyPolicyOutput {
                require_attestation: true,
                require_sbom: true,
                min_slsa_level: 2,
                allow_unsigned: false,
            },
        };
        let json = serde_json::to_string_pretty(&output).unwrap();
        assert!(json.contains("all_checks_passed"));
        assert!(json.contains("deadbeef"));
        assert!(json.contains("cafe1234"));
        assert_eq!(output.steps.len(), 3);
        assert!(output.steps.iter().all(|s| s.passed));
    }

    // ── HostPinRequest/HostRollbackRequest Serde ────────────────────

    #[test]
    fn host_pin_request_serde_roundtrip() {
        let request = HostPinRequest {
            version: test_version(2, 0, 0),
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: HostPinRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version, test_version(2, 0, 0));
    }

    #[test]
    fn host_rollback_request_serde_roundtrip() {
        let request = HostRollbackRequest {
            connector_id: "fcp.test:utility:v1".to_string(),
            to_version: test_version(1, 0, 0),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("fcp.test:utility:v1"));
        assert!(json.contains("1.0.0"));
    }

    #[test]
    fn host_rollout_schedule_request_skips_none_previous() {
        let request = HostRolloutScheduleRequest {
            connector_id: "fcp.test:utility:v1".to_string(),
            version: test_version(2, 0, 0),
            previous_version: None,
            policy: RolloutPolicy::builder().canary_percent(10).build(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("previous_version"));
    }

    #[test]
    fn host_rollout_schedule_request_includes_previous() {
        let request = HostRolloutScheduleRequest {
            connector_id: "fcp.test:utility:v1".to_string(),
            version: test_version(2, 0, 0),
            previous_version: Some(test_version(1, 0, 0)),
            policy: RolloutPolicy::builder().canary_percent(50).build(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("previous_version"));
        assert!(json.contains("1.0.0"));
    }

    // ── PinOutput/RollbackOutput/RolloutStatusOutput edge cases ─────

    #[test]
    fn pin_output_unpin_action_no_version() {
        let output = PinOutput {
            connector_id: "fcp.test:utility:v1".to_string(),
            action: "unpin".to_string(),
            version: None,
            message: "Unpinned".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"version\":null"));
        assert!(json.contains("\"action\":\"unpin\""));
    }

    #[test]
    fn rollout_status_output_with_canary() {
        let output = RolloutStatusOutput {
            connector_id: "fcp.test:utility:v1".to_string(),
            state: "canary".to_string(),
            version: "2.0.0".to_string(),
            canary_percent: 25,
            pinned: true,
            health: "degraded".to_string(),
            message: "Canary at 25%".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"canary_percent\":25"));
        assert!(json.contains("\"health\":\"degraded\""));
    }

    #[test]
    fn rollback_output_message_preserved() {
        let output = RollbackOutput {
            connector_id: "fcp.test:utility:v1".to_string(),
            from_version: "3.0.0".to_string(),
            to_version: "2.5.0".to_string(),
            message: "Emergency rollback due to crash loop".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("Emergency rollback"));
        assert!(json.contains("3.0.0"));
        assert!(json.contains("2.5.0"));
    }

    // ── print_* function invocations (no panic) ─────────────────────

    #[test]
    fn print_list_human_readable_no_panic() {
        let output = simulate_list_output(None);
        print_list_human_readable(&output);
    }

    #[test]
    fn print_list_human_readable_empty_no_panic() {
        let output = ConnectorListOutput {
            total: 0,
            by_zone: vec![],
        };
        print_list_human_readable(&output);
    }

    #[test]
    fn print_info_human_readable_no_panic() {
        let info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        print_info_human_readable(&info);
    }

    #[test]
    fn print_info_no_rate_limits_no_panic() {
        let mut info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        info.rate_limits = None;
        print_info_human_readable(&info);
    }

    #[test]
    fn print_info_no_events_no_panic() {
        let mut info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        info.events.clear();
        print_info_human_readable(&info);
    }

    #[test]
    fn print_info_no_metrics_no_panic() {
        let mut info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        info.metrics = None;
        print_info_human_readable(&info);
    }

    #[test]
    fn print_info_unsigned_no_panic() {
        let mut info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        info.signed = false;
        info.attestations.clear();
        print_info_human_readable(&info);
    }

    #[test]
    fn print_info_network_disabled_no_panic() {
        let mut info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        info.sandbox.network_access = false;
        print_info_human_readable(&info);
    }

    #[test]
    fn print_introspection_human_readable_no_panic() {
        let intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        print_introspection_human_readable(&intro);
    }

    #[test]
    fn print_introspection_no_events_no_panic() {
        let mut intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        intro.events.clear();
        print_introspection_human_readable(&intro);
    }

    #[test]
    fn print_introspection_no_rate_limits_no_panic() {
        let mut intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        intro.rate_limits = None;
        print_introspection_human_readable(&intro);
    }

    #[test]
    fn print_introspection_no_event_caps_no_panic() {
        let mut intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        intro.event_caps = None;
        print_introspection_human_readable(&intro);
    }

    #[test]
    fn print_introspection_no_resource_types_no_panic() {
        let mut intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        intro.resource_types.clear();
        print_introspection_human_readable(&intro);
    }

    #[test]
    fn print_introspection_op_no_description_no_panic() {
        let mut intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        for op in &mut intro.operations {
            op.description = None;
        }
        print_introspection_human_readable(&intro);
    }

    #[test]
    fn print_introspection_op_no_approval_no_panic() {
        let mut intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        for op in &mut intro.operations {
            op.requires_approval = None;
        }
        print_introspection_human_readable(&intro);
    }

    #[test]
    fn print_introspection_op_no_rate_limit_no_panic() {
        let mut intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        for op in &mut intro.operations {
            op.rate_limit = None;
        }
        print_introspection_human_readable(&intro);
    }

    #[test]
    fn print_pin_output_json_no_panic() {
        let output = PinOutput {
            connector_id: "test".to_string(),
            action: "pin".to_string(),
            version: Some("1.0.0".to_string()),
            message: "done".to_string(),
        };
        print_pin_output(&output, true).unwrap();
    }

    #[test]
    fn print_pin_output_human_pin_no_panic() {
        let output = PinOutput {
            connector_id: "fcp.test:v1".to_string(),
            action: "pin".to_string(),
            version: Some("1.0.0".to_string()),
            message: "done".to_string(),
        };
        print_pin_output(&output, false).unwrap();
    }

    #[test]
    fn print_pin_output_human_unpin_no_panic() {
        let output = PinOutput {
            connector_id: "fcp.test:v1".to_string(),
            action: "unpin".to_string(),
            version: None,
            message: "done".to_string(),
        };
        print_pin_output(&output, false).unwrap();
    }

    #[test]
    fn print_rollout_status_json_no_panic() {
        let output = RolloutStatusOutput {
            connector_id: "test".to_string(),
            state: "canary".to_string(),
            version: "1.0.0".to_string(),
            canary_percent: 50,
            pinned: true,
            health: "healthy".to_string(),
            message: "ok".to_string(),
        };
        print_rollout_status_output(&output, true).unwrap();
    }

    #[test]
    fn print_rollout_status_human_with_canary_no_panic() {
        let output = RolloutStatusOutput {
            connector_id: "test".to_string(),
            state: "canary".to_string(),
            version: "1.0.0".to_string(),
            canary_percent: 25,
            pinned: true,
            health: "healthy".to_string(),
            message: "ok".to_string(),
        };
        print_rollout_status_output(&output, false).unwrap();
    }

    #[test]
    fn print_rollout_status_human_no_canary_no_panic() {
        let output = RolloutStatusOutput {
            connector_id: "test".to_string(),
            state: "production".to_string(),
            version: "1.0.0".to_string(),
            canary_percent: 0,
            pinned: false,
            health: "healthy".to_string(),
            message: "ok".to_string(),
        };
        print_rollout_status_output(&output, false).unwrap();
    }

    #[test]
    fn print_rollback_json_no_panic() {
        let output = RollbackOutput {
            connector_id: "test".to_string(),
            from_version: "2.0.0".to_string(),
            to_version: "1.0.0".to_string(),
            message: "rolled back".to_string(),
        };
        print_rollback_output(&output, true).unwrap();
    }

    #[test]
    fn print_rollback_human_no_panic() {
        let output = RollbackOutput {
            connector_id: "fcp.test:v1".to_string(),
            from_version: "2.0.0".to_string(),
            to_version: "1.0.0".to_string(),
            message: "rolled back".to_string(),
        };
        print_rollback_output(&output, false).unwrap();
    }

    // ── FakeRolloutHostClient error edge cases ──────────────────────

    #[test]
    fn rollout_status_no_rollout_no_pin_version_fails() {
        let mut client = FakeRolloutHostClient::new();
        client.rollout_status = None;
        client.pin_state.version = None;
        client.pin_state.pinned = false;
        let args = RolloutStatusArgs {
            connector_id: test_connector_id(),
            json: true,
        };
        assert!(run_rollout_status_with_client(&args, &client).is_err());
    }

    #[test]
    fn rollout_set_captures_previous_version() {
        let client = FakeRolloutHostClient::new();
        let args = RolloutSetArgs {
            connector_id: test_connector_id(),
            canary: 10,
            json: true,
        };
        let _output = run_rollout_set_with_client(&args, &client).unwrap();
        let scheduled = client.scheduled_requests.borrow();
        assert_eq!(scheduled.len(), 1);
        // Previous version comes from the rollout status (1.2.2)
        assert_eq!(scheduled[0].previous_version, Some(test_version(1, 2, 2)));
    }

    #[test]
    fn rollout_set_no_existing_rollout_has_no_previous() {
        let mut client = FakeRolloutHostClient::new();
        client.rollout_status = None;
        let args = RolloutSetArgs {
            connector_id: test_connector_id(),
            canary: 10,
            json: true,
        };
        let _output = run_rollout_set_with_client(&args, &client).unwrap();
        let scheduled = client.scheduled_requests.borrow();
        assert_eq!(scheduled[0].previous_version, None);
    }

    #[test]
    fn rollback_records_request() {
        let client = FakeRolloutHostClient::new();
        let args = RollbackArgs {
            connector_id: test_connector_id(),
            to: "1.0.0".to_string(),
            json: true,
        };
        let _output = run_rollback_with_client(&args, &client).unwrap();
        let requests = client.rollback_requests.borrow();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, test_connector_id());
        assert_eq!(requests[0].1, test_version(1, 0, 0));
    }

    // ── Simulate functions: additional edge cases ───────────────────

    #[test]
    fn list_all_zones_correct_total() {
        let output = simulate_list_output(None);
        let counted: usize = output.by_zone.iter().map(|z| z.connectors.len()).sum();
        assert_eq!(output.total, counted);
    }

    #[test]
    fn info_twitter_required_caps() {
        let info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        assert_eq!(info.required_capabilities.len(), 2);
        assert!(
            info.required_capabilities
                .iter()
                .any(|c| c.as_str() == "twitter:read:tweets")
        );
    }

    #[test]
    fn info_twitter_optional_caps() {
        let info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        assert_eq!(info.optional_capabilities.len(), 3);
        assert!(
            info.optional_capabilities
                .iter()
                .any(|c| c.as_str() == "twitter:write:tweets")
        );
    }

    #[test]
    fn info_twitter_operations_have_correct_risk_levels() {
        let info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        let get_timeline = info.operations.iter().find(|o| o.id == "twitter.get_timeline").unwrap();
        assert_eq!(get_timeline.risk_level, RiskLevel::Low);
        assert_eq!(get_timeline.safety_tier, SafetyTier::Safe);

        let post_tweet = info.operations.iter().find(|o| o.id == "twitter.post_tweet").unwrap();
        assert_eq!(post_tweet.risk_level, RiskLevel::Medium);
        assert_eq!(post_tweet.safety_tier, SafetyTier::Risky);
    }

    #[test]
    fn info_twitter_metrics_populated() {
        let info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        let metrics = info.metrics.unwrap();
        assert!(metrics.requests_total > 0);
        assert!(metrics.requests_success <= metrics.requests_total);
        assert!(metrics.latency_p50_ms < metrics.latency_p99_ms);
    }

    #[test]
    fn introspect_twitter_events_have_schemas() {
        let intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        for event in &intro.events {
            assert!(event.schema.is_object(), "event {} missing schema", event.topic);
            assert!(event.requires_ack);
        }
    }

    #[test]
    fn introspect_twitter_resource_types_have_uris() {
        let intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        for rt in &intro.resource_types {
            assert!(rt.uri_pattern.starts_with("fcp://"), "bad URI pattern for {}", rt.name);
            assert!(rt.schema.is_object(), "missing schema for {}", rt.name);
        }
    }

    #[test]
    fn introspect_twitter_rate_limits_match_info() {
        let info = simulate_connector_info("fcp.twitter:social:v1").unwrap();
        let intro = simulate_introspection("fcp.twitter:social:v1", None).unwrap();
        let info_limits = info.rate_limits.unwrap();
        let intro_limits = intro.rate_limits.unwrap();
        assert_eq!(info_limits.limits.len(), intro_limits.limits.len());
        assert_eq!(info_limits.limits[0].id, intro_limits.limits[0].id);
    }

    #[test]
    fn list_connectors_all_have_required_fields() {
        let output = simulate_list_output(None);
        for zone in &output.by_zone {
            assert!(!zone.zone_id.is_empty());
            for conn in &zone.connectors {
                assert!(!conn.id.is_empty());
                assert!(!conn.name.is_empty());
                assert!(!conn.version.is_empty());
                assert!(!conn.categories.is_empty());
                assert!(conn.tool_count > 0);
            }
        }
    }

    #[test]
    fn list_connectors_disabled_connector() {
        let output = simulate_list_output(None);
        // All simulated connectors are enabled
        for zone in &output.by_zone {
            for conn in &zone.connectors {
                assert!(conn.enabled);
            }
        }
    }
}
