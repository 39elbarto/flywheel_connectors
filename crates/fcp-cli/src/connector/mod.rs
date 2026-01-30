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

use anyhow::Result;
use clap::{Args, Subcommand};

use fcp_core::{
    AgentHint, ApprovalMode, CapabilityId, ConnectorHealth, IdempotencyClass, RateLimitConfig,
    RateLimitDeclarations, RateLimitEnforcement, RateLimitPool, RateLimitScope, RateLimitUnit,
    RiskLevel, SafetyTier,
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

/// Run the connector command.
pub fn run(args: &ConnectorArgs) -> Result<()> {
    match &args.command {
        ConnectorCommand::List(list_args) => run_list(list_args),
        ConnectorCommand::Info(info_args) => run_info(info_args),
        ConnectorCommand::Introspect(introspect_args) => run_introspect(introspect_args),
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
}
