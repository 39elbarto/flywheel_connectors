//! Persistent IRC session lifecycle: long-lived connection, inbound message
//! parsing, channel/private routing, and nick-collision recovery.
//!
//! The existing [`crate::client::IrcSession`] is a short-lived session that
//! opens and closes a TCP connection per operation. This module adds
//! [`IrcPersistentSession`], which wraps the same underlying stream but
//! maintains state across multiple operations: current nick, joined channels,
//! a bounded ring buffer of received messages, and connection-state tracking.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::types::{IrcParsedEvent, IrcRouteKind, is_channel_target, parse_irc_line};

// ── Constants ──────────────────────────────────────────────────────────

/// Default capacity for the inbound message ring buffer.
pub const DEFAULT_BUFFER_CAPACITY: usize = 1000;

/// Maximum number of nick-collision retries before giving up.
pub const MAX_NICK_RETRIES: usize = 5;

// ── Connection state ───────────────────────────────────────────────────

/// The lifecycle state of a persistent IRC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// TCP connected but not yet registered (no NICK/USER sent or awaiting 001).
    Connected,
    /// Successfully registered (received `RPL_WELCOME` 001).
    Registered,
    /// Connection has been closed or lost.
    Disconnected,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connected => write!(f, "connected"),
            Self::Registered => write!(f, "registered"),
            Self::Disconnected => write!(f, "disconnected"),
        }
    }
}

// ── Parsed IRC message ─────────────────────────────────────────────────

/// A lightweight parsed representation of a single raw IRC protocol line.
///
/// This is intentionally simpler than [`IrcParsedEvent`] — it captures the
/// wire-level fields without routing or classification. Higher-level routing
/// is derived via [`MessageTarget`] and the full [`IrcParsedEvent`] pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IrcMessage {
    /// The optional `:prefix` (nick!user@host or server name).
    pub prefix: Option<String>,
    /// The IRC command (e.g. "PRIVMSG", "NOTICE", "001").
    pub command: String,
    /// Positional parameters (everything after the command, excluding trailing).
    pub params: Vec<String>,
    /// The trailing parameter (after the last `:` in the params section).
    pub trailing: Option<String>,
    /// The original raw line (trimmed of CRLF).
    pub raw: String,
}

/// Whether an inbound message was directed at a channel or is a private message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageTarget {
    /// Message to a channel (#, &, !, +).
    Channel {
        /// Channel name (e.g. "#rust").
        channel: String,
    },
    /// Private message to the bot's nick.
    Private {
        /// The nick of the sender.
        from: Option<String>,
    },
    /// Server-originated message (numeric, NOTICE from server, etc.).
    Server,
    /// Unclassified target.
    Unknown,
}

// ── Message parsing ────────────────────────────────────────────────────

/// Parse a single raw IRC line into an [`IrcMessage`].
///
/// Handles both prefixed (`:prefix COMMAND params :trailing`) and unprefixed
/// (`COMMAND params :trailing`) forms. The line should already have CRLF
/// stripped.
#[must_use]
pub fn parse_irc_message(line: &str) -> IrcMessage {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let (prefix, remainder) = trimmed.strip_prefix(':').map_or((None, trimmed), |stripped| {
        stripped.split_once(' ').map_or_else(
            || (Some(stripped.to_string()), ""),
            |(prefix_str, rest)| (Some(prefix_str.to_string()), rest.trim_start()),
        )
    });

    let (command_raw, params_section) = remainder
        .split_once(' ')
        .map_or((remainder, ""), |(cmd, rest)| (cmd, rest.trim_start()));

    let command = command_raw.to_ascii_uppercase();

    let mut params = Vec::new();
    let mut trailing = None;
    let mut remaining = params_section;

    while !remaining.is_empty() {
        if let Some(after_colon) = remaining.strip_prefix(':') {
            trailing = Some(after_colon.to_string());
            break;
        }
        let (param, next) = remaining
            .split_once(' ')
            .map_or((remaining, ""), |(p, n)| (p, n.trim_start()));
        if !param.is_empty() {
            params.push(param.to_string());
        }
        remaining = next;
    }

    IrcMessage {
        prefix,
        command,
        params,
        trailing,
        raw: trimmed.to_string(),
    }
}

/// Classify the target of an [`IrcMessage`] relative to the bot's current nick.
#[must_use]
pub fn classify_message_target(msg: &IrcMessage, my_nick: &str) -> MessageTarget {
    let cmd = msg.command.as_str();
    match cmd {
        "PRIVMSG" | "NOTICE" => {
            if let Some(target) = msg.params.first() {
                if is_channel_target(target) {
                    return MessageTarget::Channel {
                        channel: target.clone(),
                    };
                }
                if target.eq_ignore_ascii_case(my_nick) {
                    let from = msg
                        .prefix
                        .as_ref()
                        .and_then(|p| extract_nick_from_prefix(p));
                    return MessageTarget::Private { from };
                }
                // Target is some other nick
                return MessageTarget::Unknown;
            }
            MessageTarget::Unknown
        }
        "JOIN" | "PART" | "TOPIC" | "MODE" => {
            let channel = msg.params.first().or(msg.trailing.as_ref());
            if let Some(ch) = channel {
                if is_channel_target(ch) {
                    return MessageTarget::Channel {
                        channel: ch.clone(),
                    };
                }
            }
            MessageTarget::Unknown
        }
        _ => {
            // Numeric replies come from the server
            if msg.command.len() == 3 && msg.command.bytes().all(|b| b.is_ascii_digit()) {
                return MessageTarget::Server;
            }
            if matches!(cmd, "PING" | "PONG" | "ERROR") {
                return MessageTarget::Server;
            }
            MessageTarget::Unknown
        }
    }
}

/// Extract the nick portion from a prefix string like "nick!user@host" or bare "nick".
#[must_use]
pub fn extract_nick_from_prefix(prefix: &str) -> Option<String> {
    if let Some((nick, _)) = prefix.split_once('!') {
        Some(nick.to_string())
    } else if let Some((nick, _)) = prefix.split_once('@') {
        Some(nick.to_string())
    } else if prefix.contains('.') || prefix.contains(':') {
        // Looks like a server name
        None
    } else {
        Some(prefix.to_string())
    }
}

// ── Bounded ring buffer ────────────────────────────────────────────────

/// A bounded ring buffer of received IRC messages. When the buffer is full,
/// the oldest message is evicted to make room for new ones.
#[derive(Debug, Clone)]
pub struct MessageBuffer {
    buf: VecDeque<BufferedMessage>,
    capacity: usize,
    /// Total number of messages ever received (including evicted).
    total_received: u64,
}

/// A message stored in the ring buffer, tagged with receipt metadata.
#[derive(Debug, Clone)]
pub struct BufferedMessage {
    /// The parsed IRC message.
    pub message: IrcMessage,
    /// The full parsed event with routing information.
    pub event: IrcParsedEvent,
    /// Wall-clock time the message was received.
    pub received_at: Instant,
    /// Sequence number (monotonically increasing).
    pub seq: u64,
}

impl MessageBuffer {
    /// Create a new buffer with the given capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "MessageBuffer capacity must be > 0");
        Self {
            buf: VecDeque::with_capacity(capacity),
            capacity,
            total_received: 0,
        }
    }

    /// Push a message into the buffer, evicting the oldest if at capacity.
    pub fn push(&mut self, message: IrcMessage, event: IrcParsedEvent) {
        self.total_received = self.total_received.saturating_add(1);
        let entry = BufferedMessage {
            message,
            event,
            received_at: Instant::now(),
            seq: self.total_received,
        };
        if self.buf.len() >= self.capacity {
            self.buf.pop_front();
        }
        self.buf.push_back(entry);
    }

    /// Number of messages currently in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Maximum capacity of the buffer.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Total number of messages received since creation (including evicted).
    #[must_use]
    pub const fn total_received(&self) -> u64 {
        self.total_received
    }

    /// Number of messages that were evicted due to buffer overflow.
    #[must_use]
    pub fn evicted_count(&self) -> u64 {
        self.total_received.saturating_sub(self.buf.len() as u64)
    }

    /// Iterate over all buffered messages from oldest to newest.
    pub fn iter(&self) -> impl Iterator<Item = &BufferedMessage> {
        self.buf.iter()
    }

    /// Return all messages for a specific channel.
    pub fn messages_for_channel<'a>(
        &'a self,
        channel: &'a str,
    ) -> impl Iterator<Item = &'a BufferedMessage> {
        self.buf
            .iter()
            .filter(move |entry| entry.event.channel.as_deref() == Some(channel))
    }

    /// Return all private messages (not channel messages).
    pub fn private_messages(&self) -> impl Iterator<Item = &BufferedMessage> {
        self.buf
            .iter()
            .filter(|entry| entry.event.route.kind == IrcRouteKind::Private)
    }

    /// Return the last `n` messages (or all if fewer).
    #[must_use]
    pub fn last_n(&self, n: usize) -> Vec<&BufferedMessage> {
        let start = self.buf.len().saturating_sub(n);
        self.buf.iter().skip(start).collect()
    }

    /// Clear all messages from the buffer (does not reset `total_received`).
    pub fn clear(&mut self) {
        self.buf.clear();
    }
}

// ── Persistent session ─────────────────────────────────────────────────

/// A persistent IRC session that tracks connection state, nick, channels,
/// and maintains a bounded message buffer.
///
/// Unlike [`crate::client::IrcSession`], this struct is designed to survive
/// across multiple `invoke` calls, holding the authoritative state of the
/// IRC connection.
#[derive(Debug)]
pub struct IrcPersistentSession {
    /// Current effective nick (may change due to collision recovery).
    current_nick: String,
    /// The nick we originally requested.
    desired_nick: String,
    /// Set of channels we have joined.
    joined_channels: HashSet<String>,
    /// Bounded ring buffer of received messages.
    message_buffer: MessageBuffer,
    /// Current connection lifecycle state.
    state: ConnectionState,
    /// When the session was created.
    created_at: Instant,
    /// When registration completed (`RPL_WELCOME` received).
    registered_at: Option<Instant>,
    /// Number of nick-collision retries performed.
    nick_retries: usize,
    /// Server name from the `RPL_WELCOME` line, if available.
    server_name: Option<String>,
    /// The welcome message (trailing from 001), if available.
    welcome_message: Option<String>,
}

impl IrcPersistentSession {
    /// Create a new persistent session in the `Connected` state.
    #[must_use]
    pub fn new(nick: &str, buffer_capacity: usize) -> Self {
        Self {
            current_nick: nick.to_string(),
            desired_nick: nick.to_string(),
            joined_channels: HashSet::new(),
            message_buffer: MessageBuffer::new(buffer_capacity),
            state: ConnectionState::Connected,
            created_at: Instant::now(),
            registered_at: None,
            nick_retries: 0,
            server_name: None,
            welcome_message: None,
        }
    }

    /// Create a new persistent session with the default buffer capacity.
    #[must_use]
    pub fn with_default_capacity(nick: &str) -> Self {
        Self::new(nick, DEFAULT_BUFFER_CAPACITY)
    }

    // ── Accessors ──

    /// The current effective nick (may differ from desired if collision occurred).
    #[must_use]
    pub fn current_nick(&self) -> &str {
        &self.current_nick
    }

    /// The originally requested nick.
    #[must_use]
    pub fn desired_nick(&self) -> &str {
        &self.desired_nick
    }

    /// Current connection state.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    /// Whether the session is fully registered (received 001).
    #[must_use]
    pub fn is_registered(&self) -> bool {
        self.state == ConnectionState::Registered
    }

    /// Whether the session is disconnected.
    #[must_use]
    pub fn is_disconnected(&self) -> bool {
        self.state == ConnectionState::Disconnected
    }

    /// The set of currently joined channels.
    #[must_use]
    pub const fn joined_channels(&self) -> &HashSet<String> {
        &self.joined_channels
    }

    /// Whether we are currently in a specific channel.
    #[must_use]
    pub fn is_in_channel(&self, channel: &str) -> bool {
        self.joined_channels.contains(channel)
    }

    /// Access the message buffer.
    #[must_use]
    pub const fn message_buffer(&self) -> &MessageBuffer {
        &self.message_buffer
    }

    /// Duration since session creation.
    #[must_use]
    pub fn uptime(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Duration since registration, if registered.
    #[must_use]
    pub fn time_since_registration(&self) -> Option<Duration> {
        self.registered_at.map(|t| t.elapsed())
    }

    /// Number of nick-collision retries performed so far.
    #[must_use]
    pub const fn nick_retries(&self) -> usize {
        self.nick_retries
    }

    /// The server name extracted from `RPL_WELCOME`, if available.
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// The welcome message from `RPL_WELCOME`, if available.
    #[must_use]
    pub fn welcome_message(&self) -> Option<&str> {
        self.welcome_message.as_deref()
    }

    // ── State transitions ──

    /// Transition to `Disconnected` state and clear channel membership.
    pub fn mark_disconnected(&mut self) {
        self.state = ConnectionState::Disconnected;
        self.joined_channels.clear();
    }

    /// Transition to `Registered` state (call when `RPL_WELCOME` is received).
    pub fn mark_registered(&mut self) {
        self.state = ConnectionState::Registered;
        self.registered_at = Some(Instant::now());
    }

    // ── Inbound message processing ──

    /// Process a raw IRC line: parse it, update session state, and buffer it.
    ///
    /// Returns the parsed message and any state-change action that the caller
    /// should take (e.g. send a PONG, re-register with a new nick).
    #[must_use]
    pub fn process_line(&mut self, line: &str) -> (IrcMessage, SessionAction) {
        let msg = parse_irc_message(line);
        let event = parse_irc_line(line, &self.current_nick);

        let action = self.apply_state_change(&msg, &event);

        // Buffer the message
        self.message_buffer.push(msg.clone(), event);

        (msg, action)
    }

    /// Apply state changes based on a received message, returning any
    /// required outbound action.
    fn apply_state_change(&mut self, msg: &IrcMessage, _event: &IrcParsedEvent) -> SessionAction {
        match msg.command.as_str() {
            "001" => {
                self.mark_registered();
                if let Some(ref prefix) = msg.prefix {
                    self.server_name = Some(prefix.clone());
                }
                if let Some(ref trailing) = msg.trailing {
                    self.welcome_message = Some(trailing.clone());
                }
                if let Some(effective_nick) = msg.params.first() {
                    if !effective_nick.is_empty() {
                        self.current_nick.clone_from(effective_nick);
                    }
                }
                SessionAction::None
            }
            "433" => self.handle_nick_collision(),
            "PING" => {
                let payload = msg
                    .trailing
                    .as_deref()
                    .or_else(|| msg.params.first().map(String::as_str))
                    .unwrap_or("");
                SessionAction::SendPong(payload.to_string())
            }
            "JOIN" => {
                let joiner_nick = msg.prefix.as_ref().and_then(|p| extract_nick_from_prefix(p));
                if joiner_nick
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case(&self.current_nick))
                {
                    if let Some(ch) = msg.params.first().or(msg.trailing.as_ref()) {
                        self.joined_channels.insert(ch.clone());
                    }
                }
                SessionAction::None
            }
            "PART" => {
                let parter_nick = msg.prefix.as_ref().and_then(|p| extract_nick_from_prefix(p));
                if parter_nick
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case(&self.current_nick))
                {
                    if let Some(ch) = msg.params.first() {
                        self.joined_channels.remove(ch);
                    }
                }
                SessionAction::None
            }
            "KICK" => {
                if let Some(kicked_nick) = msg.params.get(1) {
                    if kicked_nick.eq_ignore_ascii_case(&self.current_nick) {
                        if let Some(ch) = msg.params.first() {
                            self.joined_channels.remove(ch);
                        }
                    }
                }
                SessionAction::None
            }
            "NICK" => {
                let changer = msg.prefix.as_ref().and_then(|p| extract_nick_from_prefix(p));
                if changer
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case(&self.current_nick))
                {
                    if let Some(nn) = msg.trailing.as_ref().or_else(|| msg.params.first()) {
                        self.current_nick.clone_from(nn);
                    }
                }
                SessionAction::None
            }
            "QUIT" => {
                let quitter = msg.prefix.as_ref().and_then(|p| extract_nick_from_prefix(p));
                if quitter
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case(&self.current_nick))
                {
                    self.mark_disconnected();
                }
                SessionAction::None
            }
            "ERROR" => {
                self.mark_disconnected();
                SessionAction::None
            }
            _ => SessionAction::None,
        }
    }

    /// Handle a nick collision (433): append `_` and request re-registration.
    fn handle_nick_collision(&mut self) -> SessionAction {
        if self.nick_retries >= MAX_NICK_RETRIES {
            self.mark_disconnected();
            return SessionAction::NickExhausted;
        }
        self.nick_retries = self.nick_retries.saturating_add(1);
        self.current_nick.push('_');
        SessionAction::ChangeNick(self.current_nick.clone())
    }

    /// Record that we have joined a channel (call after sending JOIN and
    /// receiving confirmation, or after `process_line` handles the server's
    /// JOIN echo).
    pub fn track_join(&mut self, channel: &str) {
        self.joined_channels.insert(channel.to_string());
    }

    /// Record that we have left a channel.
    pub fn track_part(&mut self, channel: &str) {
        self.joined_channels.remove(channel);
    }

    /// Produce a snapshot of the session state for diagnostics/health.
    #[must_use]
    pub fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            state: self.state,
            current_nick: self.current_nick.clone(),
            desired_nick: self.desired_nick.clone(),
            nick_retries: self.nick_retries,
            joined_channels: self.joined_channels.iter().cloned().collect(),
            buffer_len: self.message_buffer.len(),
            buffer_capacity: self.message_buffer.capacity(),
            total_received: self.message_buffer.total_received(),
            evicted_count: self.message_buffer.evicted_count(),
            server_name: self.server_name.clone(),
            welcome_message: self.welcome_message.clone(),
        }
    }
}

/// An action that the network layer should take in response to a processed
/// inbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAction {
    /// No action required.
    None,
    /// Send a PONG with the given payload.
    SendPong(String),
    /// Nick collision occurred — send `NICK <new_nick>` with this new nick.
    ChangeNick(String),
    /// All nick retry attempts exhausted — the session should be torn down.
    NickExhausted,
}

/// Serializable snapshot of the session for health/diagnostics output.
#[derive(Debug, Clone, Serialize)]
pub struct SessionSnapshot {
    pub state: ConnectionState,
    pub current_nick: String,
    pub desired_nick: String,
    pub nick_retries: usize,
    pub joined_channels: Vec<String>,
    pub buffer_len: usize,
    pub buffer_capacity: usize,
    pub total_received: u64,
    pub evicted_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome_message: Option<String>,
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_irc_message tests ──

    #[test]
    fn parse_privmsg_with_prefix() {
        let msg = parse_irc_message(":alice!user@host PRIVMSG #rust :hello world");
        assert_eq!(msg.prefix.as_deref(), Some("alice!user@host"));
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#rust"]);
        assert_eq!(msg.trailing.as_deref(), Some("hello world"));
    }

    #[test]
    fn parse_privmsg_private() {
        let msg = parse_irc_message(":bob!b@example PRIVMSG flywheel :secret stuff");
        assert_eq!(msg.prefix.as_deref(), Some("bob!b@example"));
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["flywheel"]);
        assert_eq!(msg.trailing.as_deref(), Some("secret stuff"));
    }

    #[test]
    fn parse_no_prefix() {
        let msg = parse_irc_message("PING :irc.server.com");
        assert!(msg.prefix.is_none());
        assert_eq!(msg.command, "PING");
        assert!(msg.params.is_empty());
        assert_eq!(msg.trailing.as_deref(), Some("irc.server.com"));
    }

    #[test]
    fn parse_numeric_reply() {
        let msg = parse_irc_message(":irc.example.com 001 flywheel :Welcome to IRC");
        assert_eq!(msg.prefix.as_deref(), Some("irc.example.com"));
        assert_eq!(msg.command, "001");
        assert_eq!(msg.params, vec!["flywheel"]);
        assert_eq!(msg.trailing.as_deref(), Some("Welcome to IRC"));
    }

    #[test]
    fn parse_join_with_trailing_channel() {
        let msg = parse_irc_message(":alice!u@h JOIN :#rust");
        assert_eq!(msg.command, "JOIN");
        assert!(msg.params.is_empty());
        assert_eq!(msg.trailing.as_deref(), Some("#rust"));
    }

    #[test]
    fn parse_join_with_param_channel() {
        let msg = parse_irc_message(":alice!u@h JOIN #rust");
        assert_eq!(msg.command, "JOIN");
        assert_eq!(msg.params, vec!["#rust"]);
        assert!(msg.trailing.is_none());
    }

    #[test]
    fn parse_nick_in_use() {
        let msg = parse_irc_message(":irc.example.com 433 * flywheel :Nickname is already in use.");
        assert_eq!(msg.command, "433");
        assert_eq!(msg.params, vec!["*", "flywheel"]);
        assert_eq!(msg.trailing.as_deref(), Some("Nickname is already in use."));
    }

    #[test]
    fn parse_mode_message() {
        let msg = parse_irc_message(":ChanServ!s@services MODE #rust +o alice");
        assert_eq!(msg.command, "MODE");
        assert_eq!(msg.params, vec!["#rust", "+o", "alice"]);
        assert!(msg.trailing.is_none());
    }

    #[test]
    fn parse_quit_message() {
        let msg = parse_irc_message(":alice!u@h QUIT :Leaving");
        assert_eq!(msg.command, "QUIT");
        assert!(msg.params.is_empty());
        assert_eq!(msg.trailing.as_deref(), Some("Leaving"));
    }

    #[test]
    fn parse_notice_from_server() {
        let msg = parse_irc_message(":irc.example.com NOTICE * :*** Looking up your hostname");
        assert_eq!(msg.command, "NOTICE");
        assert_eq!(msg.params, vec!["*"]);
        assert_eq!(
            msg.trailing.as_deref(),
            Some("*** Looking up your hostname")
        );
    }

    #[test]
    fn parse_part_with_reason() {
        let msg = parse_irc_message(":alice!u@h PART #rust :bye everyone");
        assert_eq!(msg.command, "PART");
        assert_eq!(msg.params, vec!["#rust"]);
        assert_eq!(msg.trailing.as_deref(), Some("bye everyone"));
    }

    #[test]
    fn parse_kick_message() {
        let msg = parse_irc_message(":op!u@h KICK #rust baduser :spam");
        assert_eq!(msg.command, "KICK");
        assert_eq!(msg.params, vec!["#rust", "baduser"]);
        assert_eq!(msg.trailing.as_deref(), Some("spam"));
    }

    #[test]
    fn parse_nick_change() {
        let msg = parse_irc_message(":oldnick!u@h NICK :newnick");
        assert_eq!(msg.command, "NICK");
        assert!(msg.params.is_empty());
        assert_eq!(msg.trailing.as_deref(), Some("newnick"));
    }

    #[test]
    fn parse_empty_trailing() {
        let msg = parse_irc_message(":server NOTICE * :");
        assert_eq!(msg.command, "NOTICE");
        assert_eq!(msg.params, vec!["*"]);
        assert_eq!(msg.trailing.as_deref(), Some(""));
    }

    #[test]
    fn parse_multiple_spaces_between_params() {
        let msg = parse_irc_message(":server 353 flywheel =  #rust :alice bob");
        assert_eq!(msg.command, "353");
        // Multiple spaces are collapsed by trim_start
        assert_eq!(msg.params, vec!["flywheel", "=", "#rust"]);
        assert_eq!(msg.trailing.as_deref(), Some("alice bob"));
    }

    #[test]
    fn parse_preserves_raw_line() {
        let raw = ":alice!u@h PRIVMSG #test :hello";
        let msg = parse_irc_message(raw);
        assert_eq!(msg.raw, raw);
    }

    #[test]
    fn parse_strips_crlf() {
        let msg = parse_irc_message("PING :server\r\n");
        assert_eq!(msg.command, "PING");
        assert_eq!(msg.trailing.as_deref(), Some("server"));
        assert!(!msg.raw.contains('\r'));
        assert!(!msg.raw.contains('\n'));
    }

    #[test]
    fn parse_error_message() {
        let msg = parse_irc_message("ERROR :Closing Link: connection timed out");
        assert!(msg.prefix.is_none());
        assert_eq!(msg.command, "ERROR");
        assert_eq!(
            msg.trailing.as_deref(),
            Some("Closing Link: connection timed out")
        );
    }

    #[test]
    fn parse_command_case_insensitive() {
        let msg = parse_irc_message(":alice!u@h privmsg #test :hi");
        assert_eq!(msg.command, "PRIVMSG");
    }

    // ── classify_message_target tests ──

    #[test]
    fn classify_channel_privmsg() {
        let msg = parse_irc_message(":alice!u@h PRIVMSG #rust :hello");
        let target = classify_message_target(&msg, "flywheel");
        assert_eq!(
            target,
            MessageTarget::Channel {
                channel: "#rust".into()
            }
        );
    }

    #[test]
    fn classify_private_privmsg() {
        let msg = parse_irc_message(":alice!u@h PRIVMSG flywheel :hello");
        let target = classify_message_target(&msg, "flywheel");
        assert_eq!(
            target,
            MessageTarget::Private {
                from: Some("alice".into())
            }
        );
    }

    #[test]
    fn classify_private_privmsg_case_insensitive() {
        let msg = parse_irc_message(":alice!u@h PRIVMSG FlyWheel :hello");
        let target = classify_message_target(&msg, "flywheel");
        assert_eq!(
            target,
            MessageTarget::Private {
                from: Some("alice".into())
            }
        );
    }

    #[test]
    fn classify_channel_notice() {
        let msg = parse_irc_message(":bot!u@h NOTICE #ops :alert");
        let target = classify_message_target(&msg, "flywheel");
        assert_eq!(
            target,
            MessageTarget::Channel {
                channel: "#ops".into()
            }
        );
    }

    #[test]
    fn classify_private_notice() {
        let msg = parse_irc_message(":nickserv!s@services NOTICE flywheel :identify now");
        let target = classify_message_target(&msg, "flywheel");
        assert_eq!(
            target,
            MessageTarget::Private {
                from: Some("nickserv".into())
            }
        );
    }

    #[test]
    fn classify_numeric_is_server() {
        let msg = parse_irc_message(":irc.example.com 001 flywheel :Welcome");
        let target = classify_message_target(&msg, "flywheel");
        assert_eq!(target, MessageTarget::Server);
    }

    #[test]
    fn classify_ping_is_server() {
        let msg = parse_irc_message("PING :irc.example.com");
        let target = classify_message_target(&msg, "flywheel");
        assert_eq!(target, MessageTarget::Server);
    }

    #[test]
    fn classify_error_is_server() {
        let msg = parse_irc_message("ERROR :Closing Link");
        let target = classify_message_target(&msg, "flywheel");
        assert_eq!(target, MessageTarget::Server);
    }

    #[test]
    fn classify_join_as_channel() {
        let msg = parse_irc_message(":alice!u@h JOIN :#rust");
        let target = classify_message_target(&msg, "flywheel");
        assert_eq!(
            target,
            MessageTarget::Channel {
                channel: "#rust".into()
            }
        );
    }

    #[test]
    fn classify_part_as_channel() {
        let msg = parse_irc_message(":alice!u@h PART #rust :bye");
        let target = classify_message_target(&msg, "flywheel");
        assert_eq!(
            target,
            MessageTarget::Channel {
                channel: "#rust".into()
            }
        );
    }

    #[test]
    fn classify_channel_prefixes() {
        // All four channel prefixes: #, &, !, +
        for prefix in &["#", "&", "!", "+"] {
            let line = format!(":alice!u@h PRIVMSG {prefix}test :hi");
            let msg = parse_irc_message(&line);
            let target = classify_message_target(&msg, "flywheel");
            assert!(
                matches!(target, MessageTarget::Channel { .. }),
                "prefix '{prefix}' should be classified as channel"
            );
        }
    }

    // ── extract_nick_from_prefix tests ──

    #[test]
    fn extract_nick_full_prefix() {
        assert_eq!(
            extract_nick_from_prefix("alice!user@host"),
            Some("alice".into())
        );
    }

    #[test]
    fn extract_nick_no_user() {
        assert_eq!(extract_nick_from_prefix("alice@host"), Some("alice".into()));
    }

    #[test]
    fn extract_nick_bare() {
        assert_eq!(extract_nick_from_prefix("alice"), Some("alice".into()));
    }

    #[test]
    fn extract_nick_server() {
        assert_eq!(extract_nick_from_prefix("irc.example.com"), None);
    }

    #[test]
    fn extract_nick_ipv6_server() {
        assert_eq!(extract_nick_from_prefix("::1"), None);
    }

    // ── MessageBuffer tests ──

    #[test]
    fn buffer_push_and_len() {
        let mut buf = MessageBuffer::new(5);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.capacity(), 5);

        let msg = parse_irc_message(":alice!u@h PRIVMSG #test :hello");
        let event = parse_irc_line(":alice!u@h PRIVMSG #test :hello", "flywheel");
        buf.push(msg, event);

        assert_eq!(buf.len(), 1);
        assert!(!buf.is_empty());
        assert_eq!(buf.total_received(), 1);
        assert_eq!(buf.evicted_count(), 0);
    }

    #[test]
    fn buffer_evicts_oldest_at_capacity() {
        let mut buf = MessageBuffer::new(3);
        for i in 0..5 {
            let line = format!(":alice!u@h PRIVMSG #test :msg {i}");
            let msg = parse_irc_message(&line);
            let event = parse_irc_line(&line, "flywheel");
            buf.push(msg, event);
        }

        assert_eq!(buf.len(), 3);
        assert_eq!(buf.total_received(), 5);
        assert_eq!(buf.evicted_count(), 2);

        // The oldest remaining should be msg 2
        let oldest = buf.iter().next().unwrap();
        assert!(oldest.message.raw.contains("msg 2"));
    }

    #[test]
    fn buffer_last_n() {
        let mut buf = MessageBuffer::new(10);
        for i in 0..5 {
            let line = format!(":alice!u@h PRIVMSG #test :msg {i}");
            let msg = parse_irc_message(&line);
            let event = parse_irc_line(&line, "flywheel");
            buf.push(msg, event);
        }

        let last2 = buf.last_n(2);
        assert_eq!(last2.len(), 2);
        assert!(last2[0].message.raw.contains("msg 3"));
        assert!(last2[1].message.raw.contains("msg 4"));
    }

    #[test]
    fn buffer_last_n_more_than_available() {
        let mut buf = MessageBuffer::new(10);
        let line = ":alice!u@h PRIVMSG #test :only one";
        let msg = parse_irc_message(line);
        let event = parse_irc_line(line, "flywheel");
        buf.push(msg, event);

        let all = buf.last_n(100);
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn buffer_messages_for_channel() {
        let mut buf = MessageBuffer::new(10);

        let lines = [
            ":alice!u@h PRIVMSG #rust :rust msg",
            ":bob!u@h PRIVMSG #python :python msg",
            ":charlie!u@h PRIVMSG #rust :another rust msg",
            ":dave!u@h PRIVMSG flywheel :private msg",
        ];
        for line in &lines {
            let msg = parse_irc_message(line);
            let event = parse_irc_line(line, "flywheel");
            buf.push(msg, event);
        }

        let rust_msgs: Vec<_> = buf.messages_for_channel("#rust").collect();
        assert_eq!(rust_msgs.len(), 2);
        assert!(rust_msgs[0].message.raw.contains("rust msg"));
        assert!(rust_msgs[1].message.raw.contains("another rust msg"));
    }

    #[test]
    fn buffer_private_messages() {
        let mut buf = MessageBuffer::new(10);

        let lines = [
            ":alice!u@h PRIVMSG #rust :channel msg",
            ":bob!u@h PRIVMSG flywheel :private one",
            ":charlie!u@h PRIVMSG flywheel :private two",
        ];
        for line in &lines {
            let msg = parse_irc_message(line);
            let event = parse_irc_line(line, "flywheel");
            buf.push(msg, event);
        }

        let privates: Vec<_> = buf.private_messages().collect();
        assert_eq!(privates.len(), 2);
    }

    #[test]
    fn buffer_clear_preserves_total() {
        let mut buf = MessageBuffer::new(10);
        for i in 0..3 {
            let line = format!(":a!u@h PRIVMSG #t :m{i}");
            let msg = parse_irc_message(&line);
            let event = parse_irc_line(&line, "fw");
            buf.push(msg, event);
        }
        assert_eq!(buf.total_received(), 3);
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.total_received(), 3);
    }

    #[test]
    fn buffer_seq_is_monotonic() {
        let mut buf = MessageBuffer::new(10);
        for i in 0..5 {
            let line = format!(":a!u@h PRIVMSG #t :m{i}");
            let msg = parse_irc_message(&line);
            let event = parse_irc_line(&line, "fw");
            buf.push(msg, event);
        }
        let seqs: Vec<u64> = buf.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn buffer_zero_capacity_panics() {
        let _buf = MessageBuffer::new(0);
    }

    // ── IrcPersistentSession tests ──

    #[test]
    fn new_session_starts_connected() {
        let session = IrcPersistentSession::with_default_capacity("flywheel");
        assert_eq!(session.state(), ConnectionState::Connected);
        assert_eq!(session.current_nick(), "flywheel");
        assert_eq!(session.desired_nick(), "flywheel");
        assert!(!session.is_registered());
        assert!(!session.is_disconnected());
        assert!(session.joined_channels().is_empty());
        assert_eq!(session.nick_retries(), 0);
    }

    #[test]
    fn process_welcome_transitions_to_registered() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let (_msg, action) =
            session.process_line(":irc.example.com 001 flywheel :Welcome to the IRC Network");
        assert_eq!(action, SessionAction::None);
        assert_eq!(session.state(), ConnectionState::Registered);
        assert!(session.is_registered());
        assert_eq!(session.server_name(), Some("irc.example.com"));
        assert_eq!(
            session.welcome_message(),
            Some("Welcome to the IRC Network")
        );
        assert!(session.time_since_registration().is_some());
    }

    #[test]
    fn welcome_updates_effective_nick() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        // Server might assign a different nick (e.g. after collision recovery)
        let _ = session.process_line(":irc.example.com 001 flywheel_ :Welcome");
        assert_eq!(session.current_nick(), "flywheel_");
    }

    #[test]
    fn nick_collision_appends_underscore() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let (_msg, action) =
            session.process_line(":irc.example.com 433 * flywheel :Nickname is already in use.");
        assert_eq!(action, SessionAction::ChangeNick("flywheel_".into()));
        assert_eq!(session.current_nick(), "flywheel_");
        assert_eq!(session.nick_retries(), 1);
    }

    #[test]
    fn nick_collision_repeated() {
        let mut session = IrcPersistentSession::with_default_capacity("fw");
        for i in 1..=MAX_NICK_RETRIES {
            let (_msg, action) =
                session.process_line(":server 433 * nick :Nickname is already in use.");
            let expected_nick = format!("fw{}", "_".repeat(i));
            assert_eq!(action, SessionAction::ChangeNick(expected_nick.clone()));
            assert_eq!(session.current_nick(), expected_nick);
            assert_eq!(session.nick_retries(), i);
        }
    }

    #[test]
    fn nick_collision_exhausted() {
        let mut session = IrcPersistentSession::new("fw", 10);
        for _ in 0..MAX_NICK_RETRIES {
            let _ = session.process_line(":server 433 * nick :Nickname is already in use.");
        }
        // One more collision should exhaust retries
        let (_msg, action) =
            session.process_line(":server 433 * nick :Nickname is already in use.");
        assert_eq!(action, SessionAction::NickExhausted);
        assert!(session.is_disconnected());
    }

    #[test]
    fn ping_returns_pong_action() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let (_msg, action) = session.process_line("PING :irc.example.com");
        assert_eq!(action, SessionAction::SendPong("irc.example.com".into()));
    }

    #[test]
    fn ping_with_param_instead_of_trailing() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let (_msg, action) = session.process_line("PING irc.example.com");
        assert_eq!(action, SessionAction::SendPong("irc.example.com".into()));
    }

    #[test]
    fn join_tracks_channel() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let _ = session.process_line(":flywheel!u@h JOIN :#rust");
        assert!(session.is_in_channel("#rust"));
        assert_eq!(session.joined_channels().len(), 1);
    }

    #[test]
    fn join_param_form_tracks_channel() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let _ = session.process_line(":flywheel!u@h JOIN #ops");
        assert!(session.is_in_channel("#ops"));
    }

    #[test]
    fn other_user_join_does_not_track() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let _ = session.process_line(":alice!u@h JOIN :#rust");
        assert!(!session.is_in_channel("#rust"));
    }

    #[test]
    fn part_removes_channel() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let _ = session.process_line(":flywheel!u@h JOIN :#rust");
        assert!(session.is_in_channel("#rust"));
        let _ = session.process_line(":flywheel!u@h PART #rust :bye");
        assert!(!session.is_in_channel("#rust"));
    }

    #[test]
    fn kick_removes_channel() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let _ = session.process_line(":flywheel!u@h JOIN :#rust");
        assert!(session.is_in_channel("#rust"));
        let _ = session.process_line(":op!u@h KICK #rust flywheel :spam");
        assert!(!session.is_in_channel("#rust"));
    }

    #[test]
    fn kick_other_user_does_not_affect_membership() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let _ = session.process_line(":flywheel!u@h JOIN :#rust");
        let _ = session.process_line(":op!u@h KICK #rust alice :spam");
        assert!(session.is_in_channel("#rust"));
    }

    #[test]
    fn nick_change_by_self_updates_nick() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let _ = session.process_line(":flywheel!u@h NICK :flywheel2");
        assert_eq!(session.current_nick(), "flywheel2");
    }

    #[test]
    fn nick_change_by_other_does_not_update() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let _ = session.process_line(":alice!u@h NICK :alice2");
        assert_eq!(session.current_nick(), "flywheel");
    }

    #[test]
    fn quit_by_self_disconnects() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let _ = session.process_line(":flywheel!u@h JOIN :#rust");
        let _ = session.process_line(":flywheel!u@h QUIT :Leaving");
        assert!(session.is_disconnected());
        assert!(session.joined_channels().is_empty());
    }

    #[test]
    fn quit_by_other_does_not_disconnect() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let _ = session.process_line(":alice!u@h QUIT :Leaving");
        assert!(session.is_registered());
    }

    #[test]
    fn error_message_disconnects() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let _ = session.process_line("ERROR :Closing Link: connection timed out");
        assert!(session.is_disconnected());
    }

    #[test]
    fn mark_disconnected_clears_channels() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let _ = session.process_line(":flywheel!u@h JOIN :#rust");
        let _ = session.process_line(":flywheel!u@h JOIN :#python");
        assert_eq!(session.joined_channels().len(), 2);
        session.mark_disconnected();
        assert!(session.joined_channels().is_empty());
        assert!(session.is_disconnected());
    }

    #[test]
    fn track_join_and_part_manual() {
        let mut session = IrcPersistentSession::with_default_capacity("flywheel");
        session.track_join("#test");
        assert!(session.is_in_channel("#test"));
        session.track_part("#test");
        assert!(!session.is_in_channel("#test"));
    }

    #[test]
    fn messages_are_buffered() {
        let mut session = IrcPersistentSession::new("flywheel", 5);
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let _ = session.process_line(":alice!u@h PRIVMSG #rust :hello");
        let _ = session.process_line(":bob!u@h PRIVMSG flywheel :secret");

        assert_eq!(session.message_buffer().len(), 3);
        assert_eq!(session.message_buffer().total_received(), 3);
    }

    #[test]
    fn buffer_respects_capacity() {
        let mut session = IrcPersistentSession::new("flywheel", 3);
        for i in 0..10 {
            let _ = session.process_line(&format!(":a!u@h PRIVMSG #t :msg{i}"));
        }
        assert_eq!(session.message_buffer().len(), 3);
        assert_eq!(session.message_buffer().total_received(), 10);
        assert_eq!(session.message_buffer().evicted_count(), 7);
    }

    #[test]
    fn snapshot_captures_state() {
        let mut session = IrcPersistentSession::new("flywheel", 100);
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome to IRC");
        let _ = session.process_line(":flywheel!u@h JOIN :#rust");
        let _ = session.process_line(":flywheel!u@h JOIN :#python");
        let _ = session.process_line(":alice!u@h PRIVMSG #rust :hello");

        let snap = session.snapshot();
        assert_eq!(snap.state, ConnectionState::Registered);
        assert_eq!(snap.current_nick, "flywheel");
        assert_eq!(snap.desired_nick, "flywheel");
        assert_eq!(snap.nick_retries, 0);
        assert_eq!(snap.joined_channels.len(), 2);
        assert_eq!(snap.buffer_len, 4);
        assert_eq!(snap.buffer_capacity, 100);
        assert_eq!(snap.total_received, 4);
        assert_eq!(snap.evicted_count, 0);
        assert_eq!(snap.server_name.as_deref(), Some("irc.example.com"));
        assert_eq!(snap.welcome_message.as_deref(), Some("Welcome to IRC"));
    }

    #[test]
    fn connection_state_display() {
        assert_eq!(ConnectionState::Connected.to_string(), "connected");
        assert_eq!(ConnectionState::Registered.to_string(), "registered");
        assert_eq!(ConnectionState::Disconnected.to_string(), "disconnected");
    }

    #[test]
    fn uptime_is_positive() {
        let session = IrcPersistentSession::with_default_capacity("flywheel");
        // Uptime should be non-negative (it's measured from creation)
        assert!(session.uptime().as_nanos() > 0 || session.uptime() == Duration::ZERO);
    }

    #[test]
    fn time_since_registration_none_when_not_registered() {
        let session = IrcPersistentSession::with_default_capacity("flywheel");
        assert!(session.time_since_registration().is_none());
    }

    #[test]
    fn full_lifecycle_scenario() {
        let mut session = IrcPersistentSession::new("mybot", 100);

        // 1. Connected state
        assert_eq!(session.state(), ConnectionState::Connected);

        // 2. Receive server notices during connect
        let _ = session.process_line(":irc.libera.chat NOTICE * :*** Looking up your hostname");

        // 3. Nick collision
        let (_, action) =
            session.process_line(":irc.libera.chat 433 * mybot :Nickname is already in use.");
        assert_eq!(action, SessionAction::ChangeNick("mybot_".into()));
        assert_eq!(session.current_nick(), "mybot_");

        // 4. Registration succeeds with new nick
        let (_, action) =
            session.process_line(":irc.libera.chat 001 mybot_ :Welcome to Libera.Chat");
        assert_eq!(action, SessionAction::None);
        assert_eq!(session.state(), ConnectionState::Registered);
        assert_eq!(session.current_nick(), "mybot_");

        // 5. Join channels
        let _ = session.process_line(":mybot_!~flywheel@gateway JOIN :#rust");
        let _ = session.process_line(":mybot_!~flywheel@gateway JOIN :#python");
        assert_eq!(session.joined_channels().len(), 2);
        assert!(session.is_in_channel("#rust"));
        assert!(session.is_in_channel("#python"));

        // 6. Receive messages
        let _ = session.process_line(":alice!u@h PRIVMSG #rust :hello everyone");
        let _ = session.process_line(":bob!u@h PRIVMSG mybot_ :hey bot");
        let _ = session.process_line(":charlie!u@h PRIVMSG #python :import this");

        // 7. Handle PING
        let (_, action) = session.process_line("PING :irc.libera.chat");
        assert_eq!(action, SessionAction::SendPong("irc.libera.chat".into()));

        // 8. Verify buffer contents
        // #rust has 2 messages: our JOIN + alice's PRIVMSG
        let rust_msgs: Vec<_> = session
            .message_buffer()
            .messages_for_channel("#rust")
            .collect();
        assert_eq!(rust_msgs.len(), 2);
        assert!(rust_msgs[1].message.raw.contains("hello everyone"));

        // Private messages include the NOTICE to * and the PRIVMSG to mybot_
        let privates: Vec<_> = session.message_buffer().private_messages().collect();
        assert_eq!(privates.len(), 2);
        assert!(privates[1].message.raw.contains("hey bot"));

        // 9. Get kicked from a channel
        let _ = session.process_line(":op!u@h KICK #python mybot_ :no bots allowed");
        assert!(!session.is_in_channel("#python"));
        assert!(session.is_in_channel("#rust"));

        // 10. Part remaining channel
        let _ = session.process_line(":mybot_!~flywheel@gateway PART #rust :goodbye");
        assert!(!session.is_in_channel("#rust"));
        assert!(session.joined_channels().is_empty());

        // 11. Snapshot
        let snap = session.snapshot();
        assert_eq!(snap.state, ConnectionState::Registered);
        assert_eq!(snap.current_nick, "mybot_");
        assert_eq!(snap.desired_nick, "mybot");
        assert_eq!(snap.nick_retries, 1);
        assert_eq!(snap.server_name.as_deref(), Some("irc.libera.chat"));

        // 12. Server error disconnects
        let _ = session.process_line("ERROR :Closing Link: timeout");
        assert!(session.is_disconnected());
        assert!(session.joined_channels().is_empty());
    }

    // ── Snapshot serialization ──

    #[test]
    fn snapshot_serializes_to_json() {
        let mut session = IrcPersistentSession::new("flywheel", 50);
        let _ = session.process_line(":irc.example.com 001 flywheel :Welcome");
        let snap = session.snapshot();
        let json = serde_json::to_value(&snap).expect("snapshot should serialize");
        assert_eq!(json["state"], "registered");
        assert_eq!(json["current_nick"], "flywheel");
        assert_eq!(json["buffer_capacity"], 50);
    }

    #[test]
    fn connection_state_serializes() {
        let json = serde_json::to_value(ConnectionState::Registered).unwrap();
        assert_eq!(json, "registered");
        let json = serde_json::to_value(ConnectionState::Connected).unwrap();
        assert_eq!(json, "connected");
        let json = serde_json::to_value(ConnectionState::Disconnected).unwrap();
        assert_eq!(json, "disconnected");
    }

    #[test]
    fn message_target_serializes() {
        let channel = MessageTarget::Channel {
            channel: "#rust".into(),
        };
        let json = serde_json::to_value(&channel).unwrap();
        assert_eq!(json["channel"]["channel"], "#rust");

        let private = MessageTarget::Private {
            from: Some("alice".into()),
        };
        let json = serde_json::to_value(&private).unwrap();
        assert_eq!(json["private"]["from"], "alice");
    }

    #[test]
    fn irc_message_serializes() {
        let msg = parse_irc_message(":alice!u@h PRIVMSG #rust :hello world");
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["command"], "PRIVMSG");
        assert_eq!(json["prefix"], "alice!u@h");
        assert_eq!(json["params"], serde_json::json!(["#rust"]));
        assert_eq!(json["trailing"], "hello world");
    }
}
