//! IRC configuration types, parsing helpers, and constants.

use std::time::Duration;

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};

// ── Port defaults ──
pub const DEFAULT_PORT_TLS: u16 = 6697;
pub const DEFAULT_PORT_PLAIN: u16 = 6667;
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_SAMPLE_LINES: usize = 20;

// ── Operation identifiers ──
pub const OP_SEND_MESSAGE: &str = "irc.messages.send";
pub const OP_JOIN_CHANNEL: &str = "irc.channels.join";
pub const OP_SAMPLE_TRANSCRIPT: &str = "irc.transcript.sample";
pub const OP_HEALTH: &str = "irc.health";

// ── Capability identifiers ──
pub const CAP_MESSAGES_WRITE: &str = "irc.messages.write";
pub const CAP_CHANNELS_WRITE: &str = "irc.channels.write";
pub const CAP_MESSAGES_READ: &str = "irc.messages.read";
pub const CAP_HEALTH_READ: &str = "irc.health.read";

/// Bounded summary of the configured IRC identity for operator-visible outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IrcConfiguredIdentity {
    pub nick: String,
    pub username: String,
    pub realname: String,
}

/// Parsed IRC prefix, retaining both the raw value and any extracted identity fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IrcPrefix {
    pub raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nick: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

/// Coarse IRC event classification for normalized transcript outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IrcEventKind {
    Privmsg,
    Notice,
    Join,
    Part,
    Quit,
    Nick,
    Mode,
    Topic,
    Ping,
    Pong,
    Numeric,
    Other,
}

/// High-level routing bucket for an IRC event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IrcRouteKind {
    Channel,
    Private,
    Server,
    System,
    Unknown,
}

/// Normalized routing metadata derived from a parsed IRC line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IrcRoute {
    pub kind: IrcRouteKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_nick: Option<String>,
}

/// Structured representation of one IRC line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IrcParsedEvent {
    pub raw: String,
    pub kind: IrcEventKind,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<IrcPrefix>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trailing: Option<String>,
    pub route: IrcRoute,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// IRC server connection configuration.
#[derive(Clone, Deserialize)]
pub struct IrcConfig {
    /// IRC server hostname.
    pub server: String,

    /// Optional port override (defaults to 6697 for TLS, 6667 for plaintext).
    #[serde(default)]
    pub port: Option<u16>,

    /// Whether to use TLS (defaults to true).
    #[serde(default = "default_true")]
    pub tls: bool,

    /// IRC nickname.
    pub nick: String,

    /// IRC username (defaults to "flywheel").
    #[serde(default = "default_username")]
    pub username: String,

    /// IRC realname (defaults to "Flywheel Connector").
    #[serde(default = "default_realname")]
    pub realname: String,

    /// Optional server password.
    #[serde(default)]
    pub password: Option<String>,

    /// Request timeout in milliseconds (defaults to 10000).
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

const fn default_true() -> bool {
    true
}

fn default_username() -> String {
    "flywheel".into()
}

fn default_realname() -> String {
    "Flywheel Connector".into()
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

impl IrcConfig {
    /// Validate the configuration, returning an error for invalid fields.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` if server or nick is empty, or timeout is zero.
    pub fn validate(&self) -> FcpResult<()> {
        validate_irc_value("server", &self.server)?;
        if self.server.chars().any(char::is_whitespace) {
            return Err(invalid_request("server must not contain whitespace"));
        }
        validate_irc_atom("nick", &self.nick, false)?;
        validate_irc_atom("username", &self.username, false)?;
        validate_irc_value("realname", &self.realname)?;
        if let Some(password) = self.password.as_deref() {
            validate_irc_value("password", password)?;
        }
        if self.request_timeout_ms == 0 {
            return Err(invalid_request(
                "request_timeout_ms must be greater than zero",
            ));
        }
        Ok(())
    }

    /// Effective port, falling back to TLS/plaintext defaults.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(if self.tls {
            DEFAULT_PORT_TLS
        } else {
            DEFAULT_PORT_PLAIN
        })
    }

    /// Timeout as a `Duration`.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    /// Build the `host:port` address string.
    #[must_use]
    pub fn address(&self) -> String {
        format!("{}:{}", self.server, self.port())
    }

    /// The configured identity surfaced in transcript-rich operation outputs.
    #[must_use]
    pub fn identity(&self) -> IrcConfiguredIdentity {
        IrcConfiguredIdentity {
            nick: self.nick.clone(),
            username: self.username.clone(),
            realname: self.realname.clone(),
        }
    }
}

fn invalid_request(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1001,
        message: message.into(),
    }
}

fn has_forbidden_irc_control(value: &str) -> bool {
    value.chars().any(|ch| matches!(ch, '\r' | '\n' | '\0'))
}

pub(crate) fn validate_irc_value(field: &str, value: &str) -> FcpResult<()> {
    if value.trim().is_empty() {
        return Err(invalid_request(format!("{field} must not be empty")));
    }
    if has_forbidden_irc_control(value) {
        return Err(invalid_request(format!(
            "{field} must not contain CR, LF, or NUL bytes"
        )));
    }
    Ok(())
}

pub(crate) fn validate_irc_atom(field: &str, value: &str, allow_commas: bool) -> FcpResult<()> {
    validate_irc_value(field, value)?;
    if value.chars().any(char::is_whitespace) {
        return Err(invalid_request(format!(
            "{field} must not contain whitespace"
        )));
    }
    if value.starts_with(':') {
        return Err(invalid_request(format!("{field} must not start with ':'")));
    }
    if !allow_commas && value.contains(',') {
        return Err(invalid_request(format!(
            "{field} must identify exactly one IRC target"
        )));
    }
    Ok(())
}

#[must_use]
pub fn is_channel_target(target: &str) -> bool {
    matches!(target.chars().next(), Some('#' | '&' | '+' | '!'))
}

#[must_use]
pub fn parse_irc_lines(lines: &[String], configured_nick: &str) -> Vec<IrcParsedEvent> {
    lines
        .iter()
        .map(|line| parse_irc_line(line, configured_nick))
        .collect()
}

#[must_use]
pub fn parse_irc_line(line: &str, configured_nick: &str) -> IrcParsedEvent {
    let (prefix, remainder) = split_prefix(line);
    let (command_raw, params_raw) = remainder
        .split_once(' ')
        .map_or((remainder, ""), |(command, rest)| {
            (command, rest.trim_start())
        });
    let (params, trailing) = parse_params(params_raw);
    let command = command_raw.to_ascii_uppercase();
    let numeric = parse_numeric(&command);
    let kind = classify_kind(&command, numeric);
    let parsed_prefix = prefix.map(parse_prefix);
    let target = primary_target(kind, &params, trailing.as_deref());
    let channel = derive_channel(kind, &params, trailing.as_deref(), target.as_deref());
    let route = derive_route(
        kind,
        target.as_deref(),
        channel.as_deref(),
        parsed_prefix.as_ref(),
        configured_nick,
    );
    let message = match kind {
        IrcEventKind::Privmsg | IrcEventKind::Notice | IrcEventKind::Quit | IrcEventKind::Topic => {
            trailing.clone()
        }
        IrcEventKind::Numeric if numeric.is_some() => trailing.clone(),
        _ => None,
    };

    IrcParsedEvent {
        raw: line.to_string(),
        kind,
        command,
        numeric,
        prefix: parsed_prefix,
        params,
        trailing,
        route,
        target,
        channel,
        message,
    }
}

fn split_prefix(line: &str) -> (Option<&str>, &str) {
    if let Some(stripped) = line.strip_prefix(':') {
        if let Some((prefix, remainder)) = stripped.split_once(' ') {
            return (Some(prefix), remainder.trim_start());
        }
    }
    (None, line)
}

fn parse_params(rest: &str) -> (Vec<String>, Option<String>) {
    let mut params = Vec::new();
    let mut trailing = None;
    let mut remaining = rest.trim_start();
    while !remaining.is_empty() {
        if let Some(after_colon) = remaining.strip_prefix(':') {
            trailing = Some(after_colon.to_string());
            break;
        }
        let (param, next) = remaining
            .split_once(' ')
            .map_or((remaining, ""), |(param, next)| (param, next.trim_start()));
        if !param.is_empty() {
            params.push(param.to_string());
        }
        remaining = next;
    }
    (params, trailing)
}

fn parse_numeric(command: &str) -> Option<u16> {
    (command.len() == 3 && command.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| command.parse::<u16>().ok())
        .flatten()
}

fn classify_kind(command: &str, numeric: Option<u16>) -> IrcEventKind {
    if numeric.is_some() {
        return IrcEventKind::Numeric;
    }
    match command {
        "PRIVMSG" => IrcEventKind::Privmsg,
        "NOTICE" => IrcEventKind::Notice,
        "JOIN" => IrcEventKind::Join,
        "PART" => IrcEventKind::Part,
        "QUIT" => IrcEventKind::Quit,
        "NICK" => IrcEventKind::Nick,
        "MODE" => IrcEventKind::Mode,
        "TOPIC" => IrcEventKind::Topic,
        "PING" => IrcEventKind::Ping,
        "PONG" => IrcEventKind::Pong,
        _ => IrcEventKind::Other,
    }
}

fn parse_prefix(raw: &str) -> IrcPrefix {
    if let Some((nick, rest)) = raw.split_once('!') {
        if let Some((user, host)) = rest.split_once('@') {
            return IrcPrefix {
                raw: raw.to_string(),
                nick: Some(nick.to_string()),
                user: Some(user.to_string()),
                host: Some(host.to_string()),
                server: None,
            };
        }
        return IrcPrefix {
            raw: raw.to_string(),
            nick: Some(nick.to_string()),
            user: Some(rest.to_string()),
            host: None,
            server: None,
        };
    }
    if let Some((nick, host)) = raw.split_once('@') {
        return IrcPrefix {
            raw: raw.to_string(),
            nick: Some(nick.to_string()),
            user: None,
            host: Some(host.to_string()),
            server: None,
        };
    }
    let looks_like_server = raw.contains('.') || raw.contains(':');
    IrcPrefix {
        raw: raw.to_string(),
        nick: (!looks_like_server).then(|| raw.to_string()),
        user: None,
        host: None,
        server: looks_like_server.then(|| raw.to_string()),
    }
}

fn primary_target(kind: IrcEventKind, params: &[String], trailing: Option<&str>) -> Option<String> {
    match kind {
        IrcEventKind::Join => params
            .first()
            .cloned()
            .or_else(|| trailing.map(std::string::ToString::to_string)),
        _ => params.first().cloned(),
    }
}

fn derive_channel(
    kind: IrcEventKind,
    params: &[String],
    trailing: Option<&str>,
    target: Option<&str>,
) -> Option<String> {
    if let Some(target) = target.filter(|target| is_channel_target(target)) {
        return Some(target.to_string());
    }
    match kind {
        IrcEventKind::Join => trailing
            .filter(|candidate| is_channel_target(candidate))
            .map(std::string::ToString::to_string),
        IrcEventKind::Numeric => params
            .iter()
            .find(|param| is_channel_target(param))
            .cloned()
            .or_else(|| {
                trailing
                    .filter(|candidate| is_channel_target(candidate))
                    .map(std::string::ToString::to_string)
            }),
        _ => None,
    }
}

fn derive_route(
    kind: IrcEventKind,
    target: Option<&str>,
    channel: Option<&str>,
    prefix: Option<&IrcPrefix>,
    configured_nick: &str,
) -> IrcRoute {
    if let Some(channel) = channel {
        return IrcRoute {
            kind: IrcRouteKind::Channel,
            conversation: Some(channel.to_string()),
            peer_nick: prefix.and_then(|prefix| prefix.nick.clone()),
        };
    }
    match kind {
        IrcEventKind::Privmsg | IrcEventKind::Notice | IrcEventKind::Nick | IrcEventKind::Quit => {
            let peer_nick = prefix.and_then(|prefix| prefix.nick.clone());
            let conversation = match target {
                Some(target) if target.eq_ignore_ascii_case(configured_nick) => {
                    peer_nick.clone().or_else(|| Some(target.to_string()))
                }
                Some(target) => Some(target.to_string()),
                None => peer_nick.clone(),
            };
            IrcRoute {
                kind: IrcRouteKind::Private,
                conversation,
                peer_nick,
            }
        }
        IrcEventKind::Numeric => IrcRoute {
            kind: IrcRouteKind::Server,
            conversation: target.map(std::string::ToString::to_string),
            peer_nick: None,
        },
        IrcEventKind::Ping | IrcEventKind::Pong => IrcRoute {
            kind: IrcRouteKind::System,
            conversation: None,
            peer_nick: None,
        },
        _ => IrcRoute {
            kind: IrcRouteKind::Unknown,
            conversation: target.map(std::string::ToString::to_string),
            peer_nick: prefix.and_then(|prefix| prefix.nick.clone()),
        },
    }
}

impl std::fmt::Debug for IrcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrcConfig")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("nick", &self.nick)
            .field("username", &self.username)
            .field("realname", &self.realname)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("tls", &self.tls)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn config_requires_server() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "",
            "nick": "flywheel"
        }))
        .expect("should deserialize");
        let err = config.validate().expect_err("empty server should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn config_requires_nick() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": ""
        }))
        .expect("should deserialize");
        let err = config.validate().expect_err("empty nick should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn config_rejects_whitespace_in_server() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc example.com",
            "nick": "flywheel"
        }))
        .expect("should deserialize");
        let err = config
            .validate()
            .expect_err("whitespace in server should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn config_rejects_whitespace_in_nick() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "fly wheel"
        }))
        .expect("should deserialize");
        let err = config
            .validate()
            .expect_err("whitespace in nick should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn config_rejects_username_with_line_breaks() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "username": "bad\nuser"
        }))
        .expect("should deserialize");
        let err = config
            .validate()
            .expect_err("username with line breaks should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "request_timeout_ms": 0
        }))
        .expect("should deserialize");
        let err = config.validate().expect_err("zero timeout should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn port_defaults_follow_tls_setting() {
        let tls_config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "tls": true
        }))
        .unwrap();
        let plain_config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "tls": false
        }))
        .unwrap();
        assert_eq!(tls_config.port(), DEFAULT_PORT_TLS);
        assert_eq!(plain_config.port(), DEFAULT_PORT_PLAIN);
    }

    #[test]
    fn explicit_port_overrides_defaults() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "tls": true,
            "port": 7000
        }))
        .unwrap();
        assert_eq!(config.port(), 7000);
    }

    #[test]
    fn timeout_returns_duration() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "request_timeout_ms": 5000
        }))
        .unwrap();
        assert_eq!(config.timeout(), Duration::from_secs(5));
    }

    #[test]
    fn address_combines_host_and_port() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "tls": true
        }))
        .unwrap();
        assert_eq!(config.address(), "irc.example.com:6697");
    }

    #[test]
    fn default_timeout_is_10_seconds() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel"
        }))
        .unwrap();
        assert_eq!(config.request_timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(config.timeout(), Duration::from_secs(10));
    }

    #[test]
    fn tls_defaults_to_true() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel"
        }))
        .unwrap();
        assert!(config.tls);
    }

    #[test]
    fn username_defaults_to_flywheel() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel"
        }))
        .unwrap();
        assert_eq!(config.username, "flywheel");
    }

    #[test]
    fn realname_defaults_to_flywheel_connector() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel"
        }))
        .unwrap();
        assert_eq!(config.realname, "Flywheel Connector");
    }

    #[test]
    fn password_defaults_to_none() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel"
        }))
        .unwrap();
        assert!(config.password.is_none());
    }

    #[test]
    fn password_can_be_set() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "password": "secret"
        }))
        .unwrap();
        assert_eq!(config.password.as_deref(), Some("secret"));
    }

    #[test]
    fn valid_config_passes_validation() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.libera.chat",
            "nick": "flywheel",
            "tls": true,
            "password": "pass123"
        }))
        .unwrap();
        config.validate().expect("valid config should pass");
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(DEFAULT_PORT_TLS, 6697);
        assert_eq!(DEFAULT_PORT_PLAIN, 6667);
        assert_eq!(DEFAULT_TIMEOUT_MS, 10_000);
        assert_eq!(DEFAULT_SAMPLE_LINES, 20);
    }

    #[test]
    fn operation_constants_match_manifest() {
        assert_eq!(OP_SEND_MESSAGE, "irc.messages.send");
        assert_eq!(OP_JOIN_CHANNEL, "irc.channels.join");
        assert_eq!(OP_SAMPLE_TRANSCRIPT, "irc.transcript.sample");
        assert_eq!(OP_HEALTH, "irc.health");
    }

    #[test]
    fn capability_constants_are_correct() {
        assert_eq!(CAP_MESSAGES_WRITE, "irc.messages.write");
        assert_eq!(CAP_CHANNELS_WRITE, "irc.channels.write");
        assert_eq!(CAP_MESSAGES_READ, "irc.messages.read");
        assert_eq!(CAP_HEALTH_READ, "irc.health.read");
    }

    #[test]
    fn identity_snapshot_matches_config() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "username": "fw",
            "realname": "Flywheel Bot"
        }))
        .unwrap();
        assert_eq!(
            config.identity(),
            IrcConfiguredIdentity {
                nick: "flywheel".into(),
                username: "fw".into(),
                realname: "Flywheel Bot".into(),
            }
        );
    }

    #[test]
    fn validate_irc_atom_rejects_multi_target_fanout() {
        let err = validate_irc_atom("target", "#rust,#ops", false)
            .expect_err("comma-separated targets should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_irc_value_rejects_line_breaks() {
        let err =
            validate_irc_value("message", "hello\r\nworld").expect_err("line breaks should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn parse_channel_privmsg_tracks_source_and_route() {
        let event = parse_irc_line(":alice!user@example PRIVMSG #rust :hello world", "flywheel");
        assert_eq!(event.kind, IrcEventKind::Privmsg);
        assert_eq!(event.channel.as_deref(), Some("#rust"));
        assert_eq!(event.route.kind, IrcRouteKind::Channel);
        assert_eq!(event.route.conversation.as_deref(), Some("#rust"));
        assert_eq!(event.route.peer_nick.as_deref(), Some("alice"));
        assert_eq!(event.message.as_deref(), Some("hello world"));
        let prefix = event.prefix.expect("prefix should parse");
        assert_eq!(prefix.nick.as_deref(), Some("alice"));
        assert_eq!(prefix.user.as_deref(), Some("user"));
        assert_eq!(prefix.host.as_deref(), Some("example"));
    }

    #[test]
    fn parse_private_notice_uses_peer_for_conversation() {
        let event = parse_irc_line(":alice NOTICE flywheel :maintenance incoming", "flywheel");
        assert_eq!(event.kind, IrcEventKind::Notice);
        assert_eq!(event.route.kind, IrcRouteKind::Private);
        assert_eq!(event.route.conversation.as_deref(), Some("alice"));
        assert_eq!(event.route.peer_nick.as_deref(), Some("alice"));
        assert_eq!(event.target.as_deref(), Some("flywheel"));
    }

    #[test]
    fn parse_numeric_reply_keeps_channel_context() {
        let event = parse_irc_line(
            ":irc.example.com 353 flywheel = #rust :flywheel alice bob",
            "flywheel",
        );
        assert_eq!(event.kind, IrcEventKind::Numeric);
        assert_eq!(event.numeric, Some(353));
        assert_eq!(event.channel.as_deref(), Some("#rust"));
        assert_eq!(event.route.kind, IrcRouteKind::Channel);
        assert_eq!(event.message.as_deref(), Some("flywheel alice bob"));
    }

    #[test]
    fn parse_join_with_bare_prefix_treats_prefix_as_nick() {
        let event = parse_irc_line(":alice JOIN :#rust", "flywheel");
        assert_eq!(event.kind, IrcEventKind::Join);
        assert_eq!(event.channel.as_deref(), Some("#rust"));
        assert_eq!(event.route.kind, IrcRouteKind::Channel);
        assert_eq!(
            event
                .prefix
                .expect("join prefix should parse")
                .nick
                .as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn parse_lines_preserves_order() {
        let parsed = parse_irc_lines(
            &[
                ":irc.example.com 001 flywheel :welcome".into(),
                ":alice!u@h PRIVMSG #rust :hi".into(),
            ],
            "flywheel",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].numeric, Some(1));
        assert_eq!(parsed[1].kind, IrcEventKind::Privmsg);
    }

    #[test]
    fn debug_redacts_password() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "password": "super_secret_password"
        }))
        .unwrap();
        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("super_secret_password"),
            "password should be redacted in Debug output"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for password"
        );
    }

    #[test]
    fn debug_without_password_shows_none() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel"
        }))
        .unwrap();
        let debug_output = format!("{config:?}");
        assert!(
            debug_output.contains("password: None"),
            "Debug output should show None when no password is set"
        );
    }
}
