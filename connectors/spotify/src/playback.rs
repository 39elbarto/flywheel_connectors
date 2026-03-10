//! `Spotify` Playback Control module.
//!
//! Provides safe playback control for the `Spotify` Web API including
//! play/pause, skip, seek, volume, shuffle, repeat, and device transfer.
//! Capabilities: `spotify.playback.read`, `spotify.playback.control`.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Device types ────────────────────────────────────────────────────

/// Type of `Spotify` Connect device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    /// Desktop or laptop computer.
    Computer,
    /// Mobile phone.
    Smartphone,
    /// Smart speaker.
    Speaker,
    /// Television.
    Tv,
    /// Gaming console.
    GameConsole,
    /// Automobile infotainment system.
    Automobile,
    /// Video casting device.
    CastVideo,
    /// Audio casting device.
    CastAudio,
    /// Unknown device type.
    Unknown,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Computer => write!(f, "Computer"),
            Self::Smartphone => write!(f, "Smartphone"),
            Self::Speaker => write!(f, "Speaker"),
            Self::Tv => write!(f, "TV"),
            Self::GameConsole => write!(f, "Game Console"),
            Self::Automobile => write!(f, "Automobile"),
            Self::CastVideo => write!(f, "Cast Video"),
            Self::CastAudio => write!(f, "Cast Audio"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Default for DeviceType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// A `Spotify` Connect device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Device ID (may be `None` for privacy reasons).
    pub id: Option<String>,
    /// Human-readable device name.
    pub name: String,
    /// Type of device.
    pub device_type: DeviceType,
    /// Current volume percentage (0-100), if available.
    pub volume_percent: Option<u8>,
    /// Whether this device is the currently active playback device.
    pub is_active: bool,
    /// Whether controlling this device is restricted.
    pub is_restricted: bool,
    /// Whether this device supports volume control.
    pub supports_volume: bool,
}

impl Device {
    /// Creates a new device with default values.
    pub fn new(name: impl Into<String>, device_type: DeviceType) -> Self {
        Self {
            id: None,
            name: name.into(),
            device_type,
            volume_percent: None,
            is_active: false,
            is_restricted: false,
            supports_volume: true,
        }
    }

    /// Returns whether the device has a known ID.
    pub const fn has_id(&self) -> bool {
        self.id.is_some()
    }
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.device_type)?;
        if self.is_active {
            write!(f, " [active]")?;
        }
        Ok(())
    }
}

// ── Playback item types ─────────────────────────────────────────────

/// Type of playback item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybackItemType {
    /// A music track.
    Track,
    /// A podcast episode.
    Episode,
    /// An advertisement.
    Ad,
    /// Unknown item type.
    Unknown,
}

impl fmt::Display for PlaybackItemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Track => write!(f, "Track"),
            Self::Episode => write!(f, "Episode"),
            Self::Ad => write!(f, "Ad"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Default for PlaybackItemType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// An item currently playing on `Spotify`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybackItem {
    /// `Spotify` ID of the item.
    pub id: Option<String>,
    /// Name of the track or episode.
    pub name: String,
    /// Artist names (empty for non-track items).
    pub artists: Vec<String>,
    /// Album name if available.
    pub album_name: Option<String>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// `Spotify` URI (e.g. `spotify:track:xxx`).
    pub uri: Option<String>,
    /// Type of the playback item.
    pub item_type: PlaybackItemType,
}

impl PlaybackItem {
    /// Creates a new track item.
    pub fn track(name: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            id: None,
            name: name.into(),
            artists: Vec::new(),
            album_name: None,
            duration_ms,
            uri: None,
            item_type: PlaybackItemType::Track,
        }
    }

    /// Creates a new episode item.
    pub fn episode(name: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            id: None,
            name: name.into(),
            artists: Vec::new(),
            album_name: None,
            duration_ms,
            uri: None,
            item_type: PlaybackItemType::Episode,
        }
    }

    /// Returns a comma-separated artist string.
    pub fn artist_display(&self) -> String {
        if self.artists.is_empty() {
            "Unknown Artist".to_owned()
        } else {
            self.artists.join(", ")
        }
    }

    /// Returns whether this is a track.
    pub const fn is_track(&self) -> bool {
        matches!(self.item_type, PlaybackItemType::Track)
    }

    /// Returns whether this is an episode.
    pub const fn is_episode(&self) -> bool {
        matches!(self.item_type, PlaybackItemType::Episode)
    }

    /// Returns whether this is an ad.
    pub const fn is_ad(&self) -> bool {
        matches!(self.item_type, PlaybackItemType::Ad)
    }
}

impl fmt::Display for PlaybackItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} - {}", self.name, self.artist_display())
    }
}

// ── Repeat mode ─────────────────────────────────────────────────────

/// Repeat mode for `Spotify` playback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepeatMode {
    /// Repeat is off.
    Off,
    /// Repeat the current track.
    Track,
    /// Repeat the current context (album, playlist, etc.).
    Context,
}

impl fmt::Display for RepeatMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::Track => write!(f, "track"),
            Self::Context => write!(f, "context"),
        }
    }
}

impl Default for RepeatMode {
    fn default() -> Self {
        Self::Off
    }
}

// ── Playback state ──────────────────────────────────────────────────

/// Current playback state from the `Spotify` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybackState {
    /// Whether playback is currently active.
    pub is_playing: bool,
    /// Current progress in milliseconds.
    pub progress_ms: Option<u64>,
    /// Active device, if any.
    pub device: Option<Device>,
    /// Currently playing item, if any.
    pub item: Option<PlaybackItem>,
    /// Whether shuffle is enabled.
    pub shuffle_state: bool,
    /// Current repeat mode.
    pub repeat_state: RepeatMode,
    /// Server timestamp when this state was captured.
    pub timestamp: u64,
}

impl PlaybackState {
    /// Creates a default idle playback state.
    pub const fn idle() -> Self {
        Self {
            is_playing: false,
            progress_ms: None,
            device: None,
            item: None,
            shuffle_state: false,
            repeat_state: RepeatMode::Off,
            timestamp: 0,
        }
    }

    /// Returns whether there is an active device.
    pub const fn has_device(&self) -> bool {
        self.device.is_some()
    }

    /// Returns whether there is a currently playing item.
    pub const fn has_item(&self) -> bool {
        self.item.is_some()
    }

    /// Returns the progress as a fraction of the total duration (0.0 to 1.0).
    pub fn progress_fraction(&self) -> Option<f64> {
        let progress = self.progress_ms?;
        let duration = self.item.as_ref()?.duration_ms;
        if duration == 0 {
            return Some(0.0);
        }
        Some(progress as f64 / duration as f64)
    }

    /// Returns the remaining time in milliseconds.
    pub fn remaining_ms(&self) -> Option<u64> {
        let progress = self.progress_ms?;
        let duration = self.item.as_ref()?.duration_ms;
        Some(duration.saturating_sub(progress))
    }
}

impl fmt::Display for PlaybackState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_playing {
            if let Some(item) = &self.item {
                write!(f, "Playing: {item}")?;
            } else {
                write!(f, "Playing (no item)")?;
            }
        } else {
            write!(f, "Paused")?;
        }
        if let Some(device) = &self.device {
            write!(f, " on {device}")?;
        }
        Ok(())
    }
}

// ── Playback commands ───────────────────────────────────────────────

/// A playback control command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PlaybackCommand {
    /// Start or resume playback.
    Play {
        /// Context URI (album, playlist, artist).
        context_uri: Option<String>,
        /// Offset within the context (track index).
        offset: Option<u32>,
        /// Position within the track in milliseconds.
        position_ms: Option<u64>,
    },
    /// Pause playback.
    Pause,
    /// Skip to the next track.
    Next,
    /// Skip to the previous track.
    Previous,
    /// Seek to a position in the current track.
    Seek {
        /// Position in milliseconds.
        position_ms: u64,
    },
    /// Set the playback volume.
    SetVolume {
        /// Volume percentage (0-100).
        volume_percent: u8,
    },
    /// Toggle shuffle mode.
    SetShuffle {
        /// Whether shuffle should be enabled.
        state: bool,
    },
    /// Set the repeat mode.
    SetRepeat {
        /// Desired repeat mode.
        mode: RepeatMode,
    },
    /// Transfer playback to another device.
    TransferPlayback {
        /// Target device ID.
        device_id: String,
        /// Whether to start playing on the new device.
        play: bool,
    },
}

impl PlaybackCommand {
    /// Returns the command name as a string.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Play { .. } => "play",
            Self::Pause => "pause",
            Self::Next => "next",
            Self::Previous => "previous",
            Self::Seek { .. } => "seek",
            Self::SetVolume { .. } => "set_volume",
            Self::SetShuffle { .. } => "set_shuffle",
            Self::SetRepeat { .. } => "set_repeat",
            Self::TransferPlayback { .. } => "transfer_playback",
        }
    }

    /// Returns whether this command modifies playback state (i.e. is a control command).
    pub const fn is_control(&self) -> bool {
        true
    }

    /// Returns a simple resume play command.
    pub const fn resume() -> Self {
        Self::Play {
            context_uri: None,
            offset: None,
            position_ms: None,
        }
    }

    /// Returns a play command with a context URI.
    pub fn play_context(uri: impl Into<String>) -> Self {
        Self::Play {
            context_uri: Some(uri.into()),
            offset: None,
            position_ms: None,
        }
    }
}

impl fmt::Display for PlaybackCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Play {
                context_uri,
                offset,
                position_ms,
            } => {
                write!(f, "Play")?;
                if let Some(uri) = context_uri {
                    write!(f, " [{uri}]")?;
                }
                if let Some(off) = offset {
                    write!(f, " @{off}")?;
                }
                if let Some(pos) = position_ms {
                    write!(f, " pos={pos}ms")?;
                }
                Ok(())
            }
            Self::Pause => write!(f, "Pause"),
            Self::Next => write!(f, "Next"),
            Self::Previous => write!(f, "Previous"),
            Self::Seek { position_ms } => write!(f, "Seek to {position_ms}ms"),
            Self::SetVolume { volume_percent } => write!(f, "Volume {volume_percent}%"),
            Self::SetShuffle { state } => {
                write!(f, "Shuffle {}", if *state { "on" } else { "off" })
            }
            Self::SetRepeat { mode } => write!(f, "Repeat {mode}"),
            Self::TransferPlayback { device_id, play } => {
                write!(
                    f,
                    "Transfer to {device_id}{}",
                    if *play { " (play)" } else { "" }
                )
            }
        }
    }
}

// ── Validation errors ───────────────────────────────────────────────

/// Errors from validating playback commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlaybackValidationError {
    /// Volume is outside the 0-100 range.
    VolumeOutOfRange {
        /// The invalid volume value.
        value: u8,
        /// Maximum allowed volume.
        max: u8,
    },
    /// Seek position is out of valid range.
    SeekOutOfRange {
        /// The invalid seek position.
        position_ms: u64,
        /// Minimum allowed.
        min_ms: u64,
        /// Maximum allowed.
        max_ms: u64,
    },
    /// No device was specified when required.
    NoDeviceSpecified,
    /// The command is restricted by policy.
    CommandRestricted {
        /// Name of the restricted command.
        command: String,
    },
    /// An empty context URI was provided.
    EmptyContextUri,
    /// An invalid offset was specified.
    InvalidOffset {
        /// The invalid offset value.
        offset: u32,
    },
}

impl fmt::Display for PlaybackValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VolumeOutOfRange { value, max } => {
                write!(f, "Volume {value} is out of range (max {max})")
            }
            Self::SeekOutOfRange {
                position_ms,
                min_ms,
                max_ms,
            } => {
                write!(
                    f,
                    "Seek position {position_ms}ms is out of range ({min_ms}ms-{max_ms}ms)"
                )
            }
            Self::NoDeviceSpecified => write!(f, "No device specified"),
            Self::CommandRestricted { command } => {
                write!(f, "Command '{command}' is restricted")
            }
            Self::EmptyContextUri => write!(f, "Empty context URI"),
            Self::InvalidOffset { offset } => {
                write!(f, "Invalid offset: {offset}")
            }
        }
    }
}

impl std::error::Error for PlaybackValidationError {}

// ── Command validator ───────────────────────────────────────────────

/// Validates playback commands against configurable constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybackCommandValidator {
    /// Maximum allowed volume (0-100).
    pub max_volume: u8,
    /// Minimum allowed seek position in milliseconds.
    pub min_seek_ms: u64,
    /// Maximum allowed seek position in milliseconds.
    pub max_seek_ms: u64,
    /// Set of allowed command names. If empty, all commands are allowed.
    pub allowed_commands: HashSet<String>,
}

impl PlaybackCommandValidator {
    /// Creates a new validator with default settings.
    pub fn new() -> Self {
        Self {
            max_volume: 100,
            min_seek_ms: 0,
            max_seek_ms: 86_400_000, // 24 hours
            allowed_commands: HashSet::new(),
        }
    }

    /// Adds a command to the allowed set.
    pub fn allow_command(&mut self, command: impl Into<String>) {
        self.allowed_commands.insert(command.into());
    }

    /// Removes a command from the allowed set.
    pub fn restrict_command(&mut self, command: &str) {
        self.allowed_commands.remove(command);
    }

    /// Validates a playback command.
    ///
    /// Returns `Ok(())` if the command passes all validation rules,
    /// or `Err` with the first validation error found.
    pub fn validate(&self, command: &PlaybackCommand) -> Result<(), PlaybackValidationError> {
        // Check if command is in the allowed set (if the set is non-empty).
        if !self.allowed_commands.is_empty() && !self.allowed_commands.contains(command.name()) {
            return Err(PlaybackValidationError::CommandRestricted {
                command: command.name().to_owned(),
            });
        }

        match command {
            PlaybackCommand::SetVolume { volume_percent } => {
                if *volume_percent > self.max_volume {
                    return Err(PlaybackValidationError::VolumeOutOfRange {
                        value: *volume_percent,
                        max: self.max_volume,
                    });
                }
            }
            PlaybackCommand::Seek { position_ms } => {
                if *position_ms < self.min_seek_ms || *position_ms > self.max_seek_ms {
                    return Err(PlaybackValidationError::SeekOutOfRange {
                        position_ms: *position_ms,
                        min_ms: self.min_seek_ms,
                        max_ms: self.max_seek_ms,
                    });
                }
            }
            PlaybackCommand::Play {
                context_uri: Some(uri),
                ..
            } => {
                if uri.is_empty() {
                    return Err(PlaybackValidationError::EmptyContextUri);
                }
            }
            PlaybackCommand::TransferPlayback { device_id, .. } => {
                if device_id.is_empty() {
                    return Err(PlaybackValidationError::NoDeviceSpecified);
                }
            }
            _ => {}
        }

        Ok(())
    }
}

impl Default for PlaybackCommandValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Audit events ────────────────────────────────────────────────────

/// An audit record of a playback command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybackAuditEvent {
    /// Timestamp of the event (Unix epoch milliseconds).
    pub timestamp: u64,
    /// Command that was executed.
    pub command: String,
    /// Target device ID, if any.
    pub device_id: Option<String>,
    /// Additional details about the command.
    pub details: String,
    /// Whether the command was allowed by policy.
    pub was_allowed: bool,
}

impl PlaybackAuditEvent {
    /// Creates a new audit event for an allowed command.
    pub fn allowed(command: &PlaybackCommand, device_id: Option<String>, timestamp: u64) -> Self {
        Self {
            timestamp,
            command: command.name().to_owned(),
            device_id,
            details: command.to_string(),
            was_allowed: true,
        }
    }

    /// Creates a new audit event for a denied command.
    pub fn denied(
        command: &PlaybackCommand,
        device_id: Option<String>,
        reason: &str,
        timestamp: u64,
    ) -> Self {
        Self {
            timestamp,
            command: command.name().to_owned(),
            device_id,
            details: format!("DENIED: {reason}"),
            was_allowed: false,
        }
    }
}

impl fmt::Display for PlaybackAuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} ({}) - {}",
            self.timestamp,
            self.command,
            if self.was_allowed {
                "allowed"
            } else {
                "denied"
            },
            self.details,
        )
    }
}

// ── Playback policy ─────────────────────────────────────────────────

/// Policy governing which playback operations are permitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct PlaybackPolicy {
    /// Whether play commands are allowed.
    pub allow_play: bool,
    /// Whether pause commands are allowed.
    pub allow_pause: bool,
    /// Whether skip (next/previous) commands are allowed.
    pub allow_skip: bool,
    /// Whether seek commands are allowed.
    pub allow_seek: bool,
    /// Whether volume control is allowed.
    pub allow_volume: bool,
    /// Whether shuffle toggling is allowed.
    pub allow_shuffle: bool,
    /// Whether repeat mode changes are allowed.
    pub allow_repeat: bool,
    /// Whether device transfer is allowed.
    pub allow_transfer: bool,
    /// Whether commands require explicit approval.
    pub require_approval: bool,
}

impl PlaybackPolicy {
    /// Creates a fully permissive policy (all operations allowed).
    pub const fn new_permissive() -> Self {
        Self {
            allow_play: true,
            allow_pause: true,
            allow_skip: true,
            allow_seek: true,
            allow_volume: true,
            allow_shuffle: true,
            allow_repeat: true,
            allow_transfer: true,
            require_approval: false,
        }
    }

    /// Creates a read-only policy (no control operations allowed).
    pub const fn new_readonly() -> Self {
        Self {
            allow_play: false,
            allow_pause: false,
            allow_skip: false,
            allow_seek: false,
            allow_volume: false,
            allow_shuffle: false,
            allow_repeat: false,
            allow_transfer: false,
            require_approval: false,
        }
    }

    /// Checks whether a command is allowed by this policy.
    ///
    /// Returns `Ok(())` if the command is permitted, or `Err` if restricted.
    pub fn check_command(&self, command: &PlaybackCommand) -> Result<(), PlaybackValidationError> {
        let allowed = match command {
            PlaybackCommand::Play { .. } => self.allow_play,
            PlaybackCommand::Pause => self.allow_pause,
            PlaybackCommand::Next | PlaybackCommand::Previous => self.allow_skip,
            PlaybackCommand::Seek { .. } => self.allow_seek,
            PlaybackCommand::SetVolume { .. } => self.allow_volume,
            PlaybackCommand::SetShuffle { .. } => self.allow_shuffle,
            PlaybackCommand::SetRepeat { .. } => self.allow_repeat,
            PlaybackCommand::TransferPlayback { .. } => self.allow_transfer,
        };

        if allowed {
            Ok(())
        } else {
            Err(PlaybackValidationError::CommandRestricted {
                command: command.name().to_owned(),
            })
        }
    }

    /// Returns the number of allowed command types.
    pub fn allowed_count(&self) -> usize {
        let flags = [
            self.allow_play,
            self.allow_pause,
            self.allow_skip,
            self.allow_seek,
            self.allow_volume,
            self.allow_shuffle,
            self.allow_repeat,
            self.allow_transfer,
        ];
        flags.iter().filter(|&&f| f).count()
    }
}

impl Default for PlaybackPolicy {
    fn default() -> Self {
        Self::new_permissive()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DeviceType tests ────────────────────────────────────────

    #[test]
    fn device_type_display_all_variants() {
        assert_eq!(DeviceType::Computer.to_string(), "Computer");
        assert_eq!(DeviceType::Smartphone.to_string(), "Smartphone");
        assert_eq!(DeviceType::Speaker.to_string(), "Speaker");
        assert_eq!(DeviceType::Tv.to_string(), "TV");
        assert_eq!(DeviceType::GameConsole.to_string(), "Game Console");
        assert_eq!(DeviceType::Automobile.to_string(), "Automobile");
        assert_eq!(DeviceType::CastVideo.to_string(), "Cast Video");
        assert_eq!(DeviceType::CastAudio.to_string(), "Cast Audio");
        assert_eq!(DeviceType::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn device_type_default_is_unknown() {
        assert_eq!(DeviceType::default(), DeviceType::Unknown);
    }

    #[test]
    fn device_type_serde_roundtrip() {
        let dt = DeviceType::GameConsole;
        let json = serde_json::to_string(&dt).unwrap();
        assert_eq!(json, "\"game_console\"");
        let back: DeviceType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, DeviceType::GameConsole);
    }

    #[test]
    fn device_type_all_serde_variants() {
        let types = [
            (DeviceType::Computer, "\"computer\""),
            (DeviceType::Smartphone, "\"smartphone\""),
            (DeviceType::Speaker, "\"speaker\""),
            (DeviceType::Tv, "\"tv\""),
            (DeviceType::GameConsole, "\"game_console\""),
            (DeviceType::Automobile, "\"automobile\""),
            (DeviceType::CastVideo, "\"cast_video\""),
            (DeviceType::CastAudio, "\"cast_audio\""),
            (DeviceType::Unknown, "\"unknown\""),
        ];
        for (dt, expected) in types {
            let json = serde_json::to_string(&dt).unwrap();
            assert_eq!(json, expected, "failed for {dt:?}");
        }
    }

    #[test]
    fn device_type_eq_and_hash() {
        let mut set = HashSet::new();
        set.insert(DeviceType::Computer);
        set.insert(DeviceType::Computer);
        set.insert(DeviceType::Smartphone);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn device_type_clone_copy() {
        let dt = DeviceType::Speaker;
        let cloned = dt;
        assert_eq!(cloned, DeviceType::Speaker);
    }

    #[test]
    fn device_type_debug() {
        let dbg = format!("{:?}", DeviceType::CastAudio);
        assert!(dbg.contains("CastAudio"));
    }

    // ── Device tests ────────────────────────────────────────────

    #[test]
    fn device_new_defaults() {
        let d = Device::new("Living Room", DeviceType::Speaker);
        assert_eq!(d.name, "Living Room");
        assert_eq!(d.device_type, DeviceType::Speaker);
        assert!(d.id.is_none());
        assert!(d.volume_percent.is_none());
        assert!(!d.is_active);
        assert!(!d.is_restricted);
        assert!(d.supports_volume);
    }

    #[test]
    fn device_has_id() {
        let mut d = Device::new("Phone", DeviceType::Smartphone);
        assert!(!d.has_id());
        d.id = Some("dev123".into());
        assert!(d.has_id());
    }

    #[test]
    fn device_display_inactive() {
        let d = Device::new("Laptop", DeviceType::Computer);
        let s = d.to_string();
        assert!(s.contains("Laptop"));
        assert!(s.contains("Computer"));
        assert!(!s.contains("[active]"));
    }

    #[test]
    fn device_display_active() {
        let mut d = Device::new("Phone", DeviceType::Smartphone);
        d.is_active = true;
        let s = d.to_string();
        assert!(s.contains("Phone"));
        assert!(s.contains("[active]"));
    }

    #[test]
    fn device_serde_roundtrip() {
        let d = Device {
            id: Some("dev1".into()),
            name: "TV Speaker".into(),
            device_type: DeviceType::Tv,
            volume_percent: Some(75),
            is_active: true,
            is_restricted: false,
            supports_volume: true,
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["name"], "TV Speaker");
        assert_eq!(json["device_type"], "tv");
        assert_eq!(json["volume_percent"], 75);
        let back: Device = serde_json::from_value(json).unwrap();
        assert_eq!(back.name, "TV Speaker");
        assert!(back.is_active);
    }

    #[test]
    fn device_serde_minimal() {
        let json = serde_json::json!({
            "name": "Test",
            "device_type": "computer",
            "is_active": false,
            "is_restricted": false,
            "supports_volume": true
        });
        let d: Device = serde_json::from_value(json).unwrap();
        assert_eq!(d.name, "Test");
        assert!(d.id.is_none());
        assert!(d.volume_percent.is_none());
    }

    #[test]
    fn device_clone_debug() {
        let d = Device::new("Car", DeviceType::Automobile);
        let cloned = d.clone();
        assert_eq!(cloned.name, "Car");
        let dbg = format!("{d:?}");
        assert!(dbg.contains("Car"));
        assert!(dbg.contains("Automobile"));
    }

    #[test]
    fn device_volume_zero() {
        let mut d = Device::new("Muted", DeviceType::Speaker);
        d.volume_percent = Some(0);
        assert_eq!(d.volume_percent, Some(0));
    }

    #[test]
    fn device_volume_max() {
        let mut d = Device::new("Loud", DeviceType::Speaker);
        d.volume_percent = Some(100);
        assert_eq!(d.volume_percent, Some(100));
    }

    // ── PlaybackItemType tests ──────────────────────────────────

    #[test]
    fn playback_item_type_display() {
        assert_eq!(PlaybackItemType::Track.to_string(), "Track");
        assert_eq!(PlaybackItemType::Episode.to_string(), "Episode");
        assert_eq!(PlaybackItemType::Ad.to_string(), "Ad");
        assert_eq!(PlaybackItemType::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn playback_item_type_default() {
        assert_eq!(PlaybackItemType::default(), PlaybackItemType::Unknown);
    }

    #[test]
    fn playback_item_type_serde_roundtrip() {
        let t = PlaybackItemType::Episode;
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"episode\"");
        let back: PlaybackItemType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, PlaybackItemType::Episode);
    }

    #[test]
    fn playback_item_type_eq_hash() {
        let mut set = HashSet::new();
        set.insert(PlaybackItemType::Track);
        set.insert(PlaybackItemType::Track);
        set.insert(PlaybackItemType::Ad);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn playback_item_type_clone_copy() {
        let t = PlaybackItemType::Track;
        let c = t;
        assert_eq!(c, PlaybackItemType::Track);
    }

    // ── PlaybackItem tests ──────────────────────────────────────

    #[test]
    fn playback_item_track_constructor() {
        let item = PlaybackItem::track("Song Name", 240_000);
        assert_eq!(item.name, "Song Name");
        assert_eq!(item.duration_ms, 240_000);
        assert_eq!(item.item_type, PlaybackItemType::Track);
        assert!(item.artists.is_empty());
        assert!(item.id.is_none());
        assert!(item.album_name.is_none());
        assert!(item.uri.is_none());
    }

    #[test]
    fn playback_item_episode_constructor() {
        let item = PlaybackItem::episode("Podcast Ep 42", 3_600_000);
        assert_eq!(item.name, "Podcast Ep 42");
        assert_eq!(item.duration_ms, 3_600_000);
        assert_eq!(item.item_type, PlaybackItemType::Episode);
    }

    #[test]
    fn playback_item_artist_display_empty() {
        let item = PlaybackItem::track("Song", 100);
        assert_eq!(item.artist_display(), "Unknown Artist");
    }

    #[test]
    fn playback_item_artist_display_single() {
        let mut item = PlaybackItem::track("Song", 100);
        item.artists = vec!["Miles Davis".to_owned()];
        assert_eq!(item.artist_display(), "Miles Davis");
    }

    #[test]
    fn playback_item_artist_display_multiple() {
        let mut item = PlaybackItem::track("Song", 100);
        item.artists = vec![
            "Artist A".to_owned(),
            "Artist B".to_owned(),
            "Artist C".to_owned(),
        ];
        assert_eq!(item.artist_display(), "Artist A, Artist B, Artist C");
    }

    #[test]
    fn playback_item_is_track() {
        let item = PlaybackItem::track("Song", 100);
        assert!(item.is_track());
        assert!(!item.is_episode());
        assert!(!item.is_ad());
    }

    #[test]
    fn playback_item_is_episode() {
        let item = PlaybackItem::episode("Ep", 100);
        assert!(item.is_episode());
        assert!(!item.is_track());
        assert!(!item.is_ad());
    }

    #[test]
    fn playback_item_is_ad() {
        let item = PlaybackItem {
            id: None,
            name: "Ad".into(),
            artists: vec![],
            album_name: None,
            duration_ms: 30_000,
            uri: None,
            item_type: PlaybackItemType::Ad,
        };
        assert!(item.is_ad());
        assert!(!item.is_track());
    }

    #[test]
    fn playback_item_display() {
        let mut item = PlaybackItem::track("Bohemian Rhapsody", 354_000);
        item.artists = vec!["Queen".to_owned()];
        let s = item.to_string();
        assert!(s.contains("Bohemian Rhapsody"));
        assert!(s.contains("Queen"));
    }

    #[test]
    fn playback_item_display_no_artist() {
        let item = PlaybackItem::track("Unknown Song", 100);
        let s = item.to_string();
        assert!(s.contains("Unknown Artist"));
    }

    #[test]
    fn playback_item_serde_roundtrip() {
        let mut item = PlaybackItem::track("Test Track", 200_000);
        item.id = Some("track123".into());
        item.artists = vec!["Artist".to_owned()];
        item.album_name = Some("Album".into());
        item.uri = Some("spotify:track:track123".into());
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["name"], "Test Track");
        assert_eq!(json["item_type"], "track");
        let back: PlaybackItem = serde_json::from_value(json).unwrap();
        assert_eq!(back.name, "Test Track");
        assert_eq!(back.duration_ms, 200_000);
    }

    #[test]
    fn playback_item_clone_debug() {
        let item = PlaybackItem::track("Clone Test", 100);
        let cloned = item.clone();
        assert_eq!(cloned.name, "Clone Test");
        let dbg = format!("{item:?}");
        assert!(dbg.contains("Clone Test"));
    }

    #[test]
    fn playback_item_zero_duration() {
        let item = PlaybackItem::track("Silent", 0);
        assert_eq!(item.duration_ms, 0);
    }

    // ── RepeatMode tests ────────────────────────────────────────

    #[test]
    fn repeat_mode_display() {
        assert_eq!(RepeatMode::Off.to_string(), "off");
        assert_eq!(RepeatMode::Track.to_string(), "track");
        assert_eq!(RepeatMode::Context.to_string(), "context");
    }

    #[test]
    fn repeat_mode_default() {
        assert_eq!(RepeatMode::default(), RepeatMode::Off);
    }

    #[test]
    fn repeat_mode_serde_roundtrip() {
        let m = RepeatMode::Context;
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"context\"");
        let back: RepeatMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, RepeatMode::Context);
    }

    #[test]
    fn repeat_mode_all_serde() {
        for mode in [RepeatMode::Off, RepeatMode::Track, RepeatMode::Context] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: RepeatMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn repeat_mode_eq_hash() {
        let mut set = HashSet::new();
        set.insert(RepeatMode::Off);
        set.insert(RepeatMode::Off);
        set.insert(RepeatMode::Track);
        assert_eq!(set.len(), 2);
    }

    // ── PlaybackState tests ─────────────────────────────────────

    #[test]
    fn playback_state_idle() {
        let state = PlaybackState::idle();
        assert!(!state.is_playing);
        assert!(state.progress_ms.is_none());
        assert!(state.device.is_none());
        assert!(state.item.is_none());
        assert!(!state.shuffle_state);
        assert_eq!(state.repeat_state, RepeatMode::Off);
        assert_eq!(state.timestamp, 0);
    }

    #[test]
    fn playback_state_has_device() {
        let mut state = PlaybackState::idle();
        assert!(!state.has_device());
        state.device = Some(Device::new("Phone", DeviceType::Smartphone));
        assert!(state.has_device());
    }

    #[test]
    fn playback_state_has_item() {
        let mut state = PlaybackState::idle();
        assert!(!state.has_item());
        state.item = Some(PlaybackItem::track("Song", 200_000));
        assert!(state.has_item());
    }

    #[test]
    fn playback_state_progress_fraction() {
        let mut state = PlaybackState::idle();
        assert!(state.progress_fraction().is_none());

        state.progress_ms = Some(50_000);
        assert!(state.progress_fraction().is_none()); // no item

        state.item = Some(PlaybackItem::track("Song", 200_000));
        let frac = state.progress_fraction().unwrap();
        assert!((frac - 0.25).abs() < 0.001);
    }

    #[test]
    fn playback_state_progress_fraction_zero_duration() {
        let mut state = PlaybackState::idle();
        state.progress_ms = Some(0);
        state.item = Some(PlaybackItem::track("Empty", 0));
        assert_eq!(state.progress_fraction(), Some(0.0));
    }

    #[test]
    fn playback_state_remaining_ms() {
        let mut state = PlaybackState::idle();
        assert!(state.remaining_ms().is_none());

        state.progress_ms = Some(50_000);
        state.item = Some(PlaybackItem::track("Song", 200_000));
        assert_eq!(state.remaining_ms(), Some(150_000));
    }

    #[test]
    fn playback_state_remaining_ms_past_duration() {
        let mut state = PlaybackState::idle();
        state.progress_ms = Some(300_000);
        state.item = Some(PlaybackItem::track("Song", 200_000));
        assert_eq!(state.remaining_ms(), Some(0)); // saturating_sub
    }

    #[test]
    fn playback_state_display_playing() {
        let mut state = PlaybackState::idle();
        state.is_playing = true;
        let mut item = PlaybackItem::track("Bohemian Rhapsody", 354_000);
        item.artists = vec!["Queen".to_owned()];
        state.item = Some(item);
        let s = state.to_string();
        assert!(s.contains("Playing"));
        assert!(s.contains("Bohemian Rhapsody"));
    }

    #[test]
    fn playback_state_display_playing_no_item() {
        let mut state = PlaybackState::idle();
        state.is_playing = true;
        let s = state.to_string();
        assert!(s.contains("Playing (no item)"));
    }

    #[test]
    fn playback_state_display_paused() {
        let state = PlaybackState::idle();
        let s = state.to_string();
        assert!(s.contains("Paused"));
    }

    #[test]
    fn playback_state_display_with_device() {
        let mut state = PlaybackState::idle();
        state.device = Some(Device::new("Laptop", DeviceType::Computer));
        let s = state.to_string();
        assert!(s.contains("Laptop"));
    }

    #[test]
    fn playback_state_serde_roundtrip() {
        let mut state = PlaybackState::idle();
        state.is_playing = true;
        state.progress_ms = Some(100_000);
        state.shuffle_state = true;
        state.repeat_state = RepeatMode::Track;
        state.timestamp = 1_700_000_000_000;
        state.item = Some(PlaybackItem::track("Test", 300_000));
        state.device = Some(Device::new("Phone", DeviceType::Smartphone));

        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["is_playing"], true);
        assert_eq!(json["shuffle_state"], true);
        assert_eq!(json["repeat_state"], "track");
        let back: PlaybackState = serde_json::from_value(json).unwrap();
        assert!(back.is_playing);
        assert_eq!(back.progress_ms, Some(100_000));
    }

    #[test]
    fn playback_state_clone_debug() {
        let state = PlaybackState::idle();
        let cloned = state.clone();
        assert!(!cloned.is_playing);
        let dbg = format!("{state:?}");
        assert!(dbg.contains("PlaybackState"));
    }

    // ── PlaybackCommand tests ───────────────────────────────────

    #[test]
    fn command_resume() {
        let cmd = PlaybackCommand::resume();
        assert_eq!(cmd.name(), "play");
        assert!(cmd.is_control());
        if let PlaybackCommand::Play {
            context_uri,
            offset,
            position_ms,
        } = &cmd
        {
            assert!(context_uri.is_none());
            assert!(offset.is_none());
            assert!(position_ms.is_none());
        } else {
            panic!("Expected Play variant");
        }
    }

    #[test]
    fn command_play_context() {
        let cmd = PlaybackCommand::play_context("spotify:album:abc123");
        if let PlaybackCommand::Play { context_uri, .. } = &cmd {
            assert_eq!(context_uri.as_deref(), Some("spotify:album:abc123"));
        } else {
            panic!("Expected Play variant");
        }
    }

    #[test]
    fn command_names() {
        assert_eq!(PlaybackCommand::resume().name(), "play");
        assert_eq!(PlaybackCommand::Pause.name(), "pause");
        assert_eq!(PlaybackCommand::Next.name(), "next");
        assert_eq!(PlaybackCommand::Previous.name(), "previous");
        assert_eq!(PlaybackCommand::Seek { position_ms: 0 }.name(), "seek");
        assert_eq!(
            PlaybackCommand::SetVolume { volume_percent: 50 }.name(),
            "set_volume"
        );
        assert_eq!(
            PlaybackCommand::SetShuffle { state: true }.name(),
            "set_shuffle"
        );
        assert_eq!(
            PlaybackCommand::SetRepeat {
                mode: RepeatMode::Off
            }
            .name(),
            "set_repeat"
        );
        assert_eq!(
            PlaybackCommand::TransferPlayback {
                device_id: "d1".into(),
                play: false,
            }
            .name(),
            "transfer_playback"
        );
    }

    #[test]
    fn command_is_control_all() {
        assert!(PlaybackCommand::resume().is_control());
        assert!(PlaybackCommand::Pause.is_control());
        assert!(PlaybackCommand::Next.is_control());
        assert!(PlaybackCommand::Previous.is_control());
        assert!(PlaybackCommand::Seek { position_ms: 0 }.is_control());
    }

    #[test]
    fn command_display_play_simple() {
        let cmd = PlaybackCommand::resume();
        let s = cmd.to_string();
        assert_eq!(s, "Play");
    }

    #[test]
    fn command_display_play_with_context() {
        let cmd = PlaybackCommand::Play {
            context_uri: Some("spotify:album:xyz".into()),
            offset: Some(3),
            position_ms: Some(5000),
        };
        let s = cmd.to_string();
        assert!(s.contains("spotify:album:xyz"));
        assert!(s.contains("@3"));
        assert!(s.contains("pos=5000ms"));
    }

    #[test]
    fn command_display_pause() {
        assert_eq!(PlaybackCommand::Pause.to_string(), "Pause");
    }

    #[test]
    fn command_display_next() {
        assert_eq!(PlaybackCommand::Next.to_string(), "Next");
    }

    #[test]
    fn command_display_previous() {
        assert_eq!(PlaybackCommand::Previous.to_string(), "Previous");
    }

    #[test]
    fn command_display_seek() {
        let s = PlaybackCommand::Seek {
            position_ms: 120_000,
        }
        .to_string();
        assert!(s.contains("120000ms"));
    }

    #[test]
    fn command_display_volume() {
        let s = PlaybackCommand::SetVolume { volume_percent: 75 }.to_string();
        assert!(s.contains("75%"));
    }

    #[test]
    fn command_display_shuffle_on() {
        let s = PlaybackCommand::SetShuffle { state: true }.to_string();
        assert!(s.contains("on"));
    }

    #[test]
    fn command_display_shuffle_off() {
        let s = PlaybackCommand::SetShuffle { state: false }.to_string();
        assert!(s.contains("off"));
    }

    #[test]
    fn command_display_repeat() {
        let s = PlaybackCommand::SetRepeat {
            mode: RepeatMode::Context,
        }
        .to_string();
        assert!(s.contains("context"));
    }

    #[test]
    fn command_display_transfer() {
        let s = PlaybackCommand::TransferPlayback {
            device_id: "dev1".into(),
            play: true,
        }
        .to_string();
        assert!(s.contains("dev1"));
        assert!(s.contains("(play)"));
    }

    #[test]
    fn command_display_transfer_no_play() {
        let s = PlaybackCommand::TransferPlayback {
            device_id: "dev1".into(),
            play: false,
        }
        .to_string();
        assert!(s.contains("dev1"));
        assert!(!s.contains("(play)"));
    }

    #[test]
    fn command_serde_roundtrip_play() {
        let cmd = PlaybackCommand::Play {
            context_uri: Some("spotify:playlist:abc".into()),
            offset: Some(5),
            position_ms: Some(10_000),
        };
        let json = serde_json::to_value(&cmd).unwrap();
        assert_eq!(json["type"], "play");
        let back: PlaybackCommand = serde_json::from_value(json).unwrap();
        assert_eq!(back, cmd);
    }

    #[test]
    fn command_serde_roundtrip_pause() {
        let cmd = PlaybackCommand::Pause;
        let json = serde_json::to_value(&cmd).unwrap();
        assert_eq!(json["type"], "pause");
        let back: PlaybackCommand = serde_json::from_value(json).unwrap();
        assert_eq!(back, cmd);
    }

    #[test]
    fn command_serde_roundtrip_seek() {
        let cmd = PlaybackCommand::Seek {
            position_ms: 42_000,
        };
        let json = serde_json::to_value(&cmd).unwrap();
        let back: PlaybackCommand = serde_json::from_value(json).unwrap();
        assert_eq!(back, cmd);
    }

    #[test]
    fn command_serde_roundtrip_volume() {
        let cmd = PlaybackCommand::SetVolume { volume_percent: 80 };
        let json = serde_json::to_value(&cmd).unwrap();
        let back: PlaybackCommand = serde_json::from_value(json).unwrap();
        assert_eq!(back, cmd);
    }

    #[test]
    fn command_serde_roundtrip_transfer() {
        let cmd = PlaybackCommand::TransferPlayback {
            device_id: "device_abc".into(),
            play: true,
        };
        let json = serde_json::to_value(&cmd).unwrap();
        let back: PlaybackCommand = serde_json::from_value(json).unwrap();
        assert_eq!(back, cmd);
    }

    #[test]
    fn command_clone_eq() {
        let cmd = PlaybackCommand::Next;
        #[allow(clippy::redundant_clone)]
        let cloned = cmd.clone();
        assert_eq!(cloned, PlaybackCommand::Next);
    }

    #[test]
    fn command_debug() {
        let dbg = format!("{:?}", PlaybackCommand::Previous);
        assert!(dbg.contains("Previous"));
    }

    // ── PlaybackValidationError tests ───────────────────────────

    #[test]
    fn validation_error_display_volume() {
        let e = PlaybackValidationError::VolumeOutOfRange {
            value: 150,
            max: 100,
        };
        let s = e.to_string();
        assert!(s.contains("150"));
        assert!(s.contains("100"));
    }

    #[test]
    fn validation_error_display_seek() {
        let e = PlaybackValidationError::SeekOutOfRange {
            position_ms: 999_999,
            min_ms: 0,
            max_ms: 500_000,
        };
        let s = e.to_string();
        assert!(s.contains("999999"));
        assert!(s.contains("500000"));
    }

    #[test]
    fn validation_error_display_no_device() {
        let e = PlaybackValidationError::NoDeviceSpecified;
        assert_eq!(e.to_string(), "No device specified");
    }

    #[test]
    fn validation_error_display_restricted() {
        let e = PlaybackValidationError::CommandRestricted {
            command: "play".into(),
        };
        let s = e.to_string();
        assert!(s.contains("play"));
        assert!(s.contains("restricted"));
    }

    #[test]
    fn validation_error_display_empty_uri() {
        let e = PlaybackValidationError::EmptyContextUri;
        assert_eq!(e.to_string(), "Empty context URI");
    }

    #[test]
    fn validation_error_display_invalid_offset() {
        let e = PlaybackValidationError::InvalidOffset { offset: 9999 };
        let s = e.to_string();
        assert!(s.contains("9999"));
    }

    #[test]
    fn validation_error_is_std_error() {
        let e = PlaybackValidationError::NoDeviceSpecified;
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn validation_error_serde_roundtrip() {
        let e = PlaybackValidationError::VolumeOutOfRange {
            value: 110,
            max: 80,
        };
        let json = serde_json::to_value(&e).unwrap();
        let back: PlaybackValidationError = serde_json::from_value(json).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn validation_error_eq() {
        let a = PlaybackValidationError::EmptyContextUri;
        let b = PlaybackValidationError::EmptyContextUri;
        assert_eq!(a, b);
        let c = PlaybackValidationError::NoDeviceSpecified;
        assert_ne!(a, c);
    }

    #[test]
    fn validation_error_clone_debug() {
        let e = PlaybackValidationError::NoDeviceSpecified;
        let cloned = e.clone();
        assert_eq!(cloned, e);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("NoDeviceSpecified"));
    }

    // ── PlaybackCommandValidator tests ──────────────────────────

    #[test]
    fn validator_new_defaults() {
        let v = PlaybackCommandValidator::new();
        assert_eq!(v.max_volume, 100);
        assert_eq!(v.min_seek_ms, 0);
        assert_eq!(v.max_seek_ms, 86_400_000);
        assert!(v.allowed_commands.is_empty());
    }

    #[test]
    fn validator_default_impl() {
        let v = PlaybackCommandValidator::default();
        assert_eq!(v.max_volume, 100);
    }

    #[test]
    fn validator_allows_all_by_default() {
        let v = PlaybackCommandValidator::new();
        assert!(v.validate(&PlaybackCommand::Pause).is_ok());
        assert!(v.validate(&PlaybackCommand::Next).is_ok());
        assert!(v.validate(&PlaybackCommand::resume()).is_ok());
    }

    #[test]
    fn validator_volume_in_range() {
        let v = PlaybackCommandValidator::new();
        assert!(
            v.validate(&PlaybackCommand::SetVolume { volume_percent: 50 })
                .is_ok()
        );
        assert!(
            v.validate(&PlaybackCommand::SetVolume { volume_percent: 0 })
                .is_ok()
        );
        assert!(
            v.validate(&PlaybackCommand::SetVolume {
                volume_percent: 100
            })
            .is_ok()
        );
    }

    #[test]
    fn validator_volume_custom_max() {
        let mut v = PlaybackCommandValidator::new();
        v.max_volume = 80;
        assert!(
            v.validate(&PlaybackCommand::SetVolume { volume_percent: 80 })
                .is_ok()
        );
        let err = v
            .validate(&PlaybackCommand::SetVolume { volume_percent: 81 })
            .unwrap_err();
        assert!(matches!(
            err,
            PlaybackValidationError::VolumeOutOfRange { value: 81, max: 80 }
        ));
    }

    #[test]
    fn validator_seek_in_range() {
        let v = PlaybackCommandValidator::new();
        assert!(
            v.validate(&PlaybackCommand::Seek { position_ms: 0 })
                .is_ok()
        );
        assert!(
            v.validate(&PlaybackCommand::Seek {
                position_ms: 1_000_000
            })
            .is_ok()
        );
    }

    #[test]
    fn validator_seek_out_of_range() {
        let mut v = PlaybackCommandValidator::new();
        v.max_seek_ms = 300_000;
        let err = v
            .validate(&PlaybackCommand::Seek {
                position_ms: 300_001,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            PlaybackValidationError::SeekOutOfRange { .. }
        ));
    }

    #[test]
    fn validator_seek_below_minimum() {
        let mut v = PlaybackCommandValidator::new();
        v.min_seek_ms = 1000;
        let err = v
            .validate(&PlaybackCommand::Seek { position_ms: 500 })
            .unwrap_err();
        assert!(matches!(
            err,
            PlaybackValidationError::SeekOutOfRange { .. }
        ));
    }

    #[test]
    fn validator_empty_context_uri() {
        let v = PlaybackCommandValidator::new();
        let cmd = PlaybackCommand::Play {
            context_uri: Some(String::new()),
            offset: None,
            position_ms: None,
        };
        let err = v.validate(&cmd).unwrap_err();
        assert_eq!(err, PlaybackValidationError::EmptyContextUri);
    }

    #[test]
    fn validator_valid_context_uri() {
        let v = PlaybackCommandValidator::new();
        let cmd = PlaybackCommand::play_context("spotify:album:abc");
        assert!(v.validate(&cmd).is_ok());
    }

    #[test]
    fn validator_transfer_empty_device() {
        let v = PlaybackCommandValidator::new();
        let cmd = PlaybackCommand::TransferPlayback {
            device_id: String::new(),
            play: false,
        };
        let err = v.validate(&cmd).unwrap_err();
        assert_eq!(err, PlaybackValidationError::NoDeviceSpecified);
    }

    #[test]
    fn validator_transfer_valid_device() {
        let v = PlaybackCommandValidator::new();
        let cmd = PlaybackCommand::TransferPlayback {
            device_id: "dev123".into(),
            play: true,
        };
        assert!(v.validate(&cmd).is_ok());
    }

    #[test]
    fn validator_allow_command() {
        let mut v = PlaybackCommandValidator::new();
        v.allow_command("play");
        v.allow_command("pause");
        assert!(v.validate(&PlaybackCommand::resume()).is_ok());
        assert!(v.validate(&PlaybackCommand::Pause).is_ok());
        let err = v.validate(&PlaybackCommand::Next).unwrap_err();
        assert!(matches!(
            err,
            PlaybackValidationError::CommandRestricted { .. }
        ));
    }

    #[test]
    fn validator_restrict_command() {
        let mut v = PlaybackCommandValidator::new();
        v.allow_command("play");
        v.allow_command("pause");
        v.allow_command("next");
        assert!(v.validate(&PlaybackCommand::Next).is_ok());
        v.restrict_command("next");
        let err = v.validate(&PlaybackCommand::Next).unwrap_err();
        assert!(matches!(
            err,
            PlaybackValidationError::CommandRestricted { .. }
        ));
    }

    #[test]
    fn validator_serde_roundtrip() {
        let mut v = PlaybackCommandValidator::new();
        v.max_volume = 75;
        v.allow_command("play");
        let json = serde_json::to_value(&v).unwrap();
        let back: PlaybackCommandValidator = serde_json::from_value(json).unwrap();
        assert_eq!(back.max_volume, 75);
        assert!(back.allowed_commands.contains("play"));
    }

    #[test]
    fn validator_clone_debug() {
        let v = PlaybackCommandValidator::new();
        let cloned = v.clone();
        assert_eq!(cloned.max_volume, 100);
        let dbg = format!("{v:?}");
        assert!(dbg.contains("PlaybackCommandValidator"));
    }

    // ── PlaybackAuditEvent tests ────────────────────────────────

    #[test]
    fn audit_event_allowed() {
        let cmd = PlaybackCommand::Pause;
        let evt = PlaybackAuditEvent::allowed(&cmd, Some("dev1".into()), 1_700_000_000);
        assert_eq!(evt.command, "pause");
        assert_eq!(evt.device_id, Some("dev1".into()));
        assert!(evt.was_allowed);
        assert_eq!(evt.timestamp, 1_700_000_000);
        assert!(evt.details.contains("Pause"));
    }

    #[test]
    fn audit_event_denied() {
        let cmd = PlaybackCommand::Next;
        let evt = PlaybackAuditEvent::denied(&cmd, None, "restricted by policy", 999);
        assert_eq!(evt.command, "next");
        assert!(evt.device_id.is_none());
        assert!(!evt.was_allowed);
        assert!(evt.details.contains("DENIED"));
        assert!(evt.details.contains("restricted by policy"));
    }

    #[test]
    fn audit_event_display_allowed() {
        let cmd = PlaybackCommand::SetVolume { volume_percent: 50 };
        let evt = PlaybackAuditEvent::allowed(&cmd, None, 100);
        let s = evt.to_string();
        assert!(s.contains("[100]"));
        assert!(s.contains("set_volume"));
        assert!(s.contains("allowed"));
    }

    #[test]
    fn audit_event_display_denied() {
        let cmd = PlaybackCommand::Pause;
        let evt = PlaybackAuditEvent::denied(&cmd, None, "not allowed", 200);
        let s = evt.to_string();
        assert!(s.contains("denied"));
        assert!(s.contains("DENIED"));
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let cmd = PlaybackCommand::Next;
        let evt = PlaybackAuditEvent::allowed(&cmd, Some("d1".into()), 555);
        let json = serde_json::to_value(&evt).unwrap();
        assert_eq!(json["command"], "next");
        let back: PlaybackAuditEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back.command, "next");
        assert!(back.was_allowed);
    }

    #[test]
    fn audit_event_clone_debug() {
        let cmd = PlaybackCommand::Pause;
        let evt = PlaybackAuditEvent::allowed(&cmd, None, 0);
        let cloned = evt.clone();
        assert_eq!(cloned.command, "pause");
        let dbg = format!("{evt:?}");
        assert!(dbg.contains("PlaybackAuditEvent"));
    }

    // ── PlaybackPolicy tests ────────────────────────────────────

    #[test]
    fn policy_permissive_defaults() {
        let p = PlaybackPolicy::new_permissive();
        assert!(p.allow_play);
        assert!(p.allow_pause);
        assert!(p.allow_skip);
        assert!(p.allow_seek);
        assert!(p.allow_volume);
        assert!(p.allow_shuffle);
        assert!(p.allow_repeat);
        assert!(p.allow_transfer);
        assert!(!p.require_approval);
    }

    #[test]
    fn policy_readonly_all_denied() {
        let p = PlaybackPolicy::new_readonly();
        assert!(!p.allow_play);
        assert!(!p.allow_pause);
        assert!(!p.allow_skip);
        assert!(!p.allow_seek);
        assert!(!p.allow_volume);
        assert!(!p.allow_shuffle);
        assert!(!p.allow_repeat);
        assert!(!p.allow_transfer);
        assert!(!p.require_approval);
    }

    #[test]
    fn policy_default_is_permissive() {
        let p = PlaybackPolicy::default();
        assert!(p.allow_play);
        assert_eq!(p.allowed_count(), 8);
    }

    #[test]
    fn policy_allowed_count_permissive() {
        let p = PlaybackPolicy::new_permissive();
        assert_eq!(p.allowed_count(), 8);
    }

    #[test]
    fn policy_allowed_count_readonly() {
        let p = PlaybackPolicy::new_readonly();
        assert_eq!(p.allowed_count(), 0);
    }

    #[test]
    fn policy_allowed_count_partial() {
        let mut p = PlaybackPolicy::new_readonly();
        p.allow_play = true;
        p.allow_pause = true;
        assert_eq!(p.allowed_count(), 2);
    }

    #[test]
    fn policy_check_command_permissive() {
        let p = PlaybackPolicy::new_permissive();
        assert!(p.check_command(&PlaybackCommand::resume()).is_ok());
        assert!(p.check_command(&PlaybackCommand::Pause).is_ok());
        assert!(p.check_command(&PlaybackCommand::Next).is_ok());
        assert!(p.check_command(&PlaybackCommand::Previous).is_ok());
        assert!(
            p.check_command(&PlaybackCommand::Seek { position_ms: 100 })
                .is_ok()
        );
        assert!(
            p.check_command(&PlaybackCommand::SetVolume { volume_percent: 50 })
                .is_ok()
        );
        assert!(
            p.check_command(&PlaybackCommand::SetShuffle { state: true })
                .is_ok()
        );
        assert!(
            p.check_command(&PlaybackCommand::SetRepeat {
                mode: RepeatMode::Track
            })
            .is_ok()
        );
        assert!(
            p.check_command(&PlaybackCommand::TransferPlayback {
                device_id: "d1".into(),
                play: false,
            })
            .is_ok()
        );
    }

    #[test]
    fn policy_check_command_readonly_blocks_all() {
        let p = PlaybackPolicy::new_readonly();
        assert!(p.check_command(&PlaybackCommand::resume()).is_err());
        assert!(p.check_command(&PlaybackCommand::Pause).is_err());
        assert!(p.check_command(&PlaybackCommand::Next).is_err());
        assert!(p.check_command(&PlaybackCommand::Previous).is_err());
        assert!(
            p.check_command(&PlaybackCommand::Seek { position_ms: 0 })
                .is_err()
        );
        assert!(
            p.check_command(&PlaybackCommand::SetVolume { volume_percent: 0 })
                .is_err()
        );
        assert!(
            p.check_command(&PlaybackCommand::SetShuffle { state: false })
                .is_err()
        );
        assert!(
            p.check_command(&PlaybackCommand::SetRepeat {
                mode: RepeatMode::Off
            })
            .is_err()
        );
        assert!(
            p.check_command(&PlaybackCommand::TransferPlayback {
                device_id: "d".into(),
                play: false,
            })
            .is_err()
        );
    }

    #[test]
    fn policy_check_play_only() {
        let mut p = PlaybackPolicy::new_readonly();
        p.allow_play = true;
        assert!(p.check_command(&PlaybackCommand::resume()).is_ok());
        assert!(p.check_command(&PlaybackCommand::Pause).is_err());
        assert!(p.check_command(&PlaybackCommand::Next).is_err());
    }

    #[test]
    fn policy_check_skip_covers_next_and_previous() {
        let mut p = PlaybackPolicy::new_readonly();
        p.allow_skip = true;
        assert!(p.check_command(&PlaybackCommand::Next).is_ok());
        assert!(p.check_command(&PlaybackCommand::Previous).is_ok());
        assert!(p.check_command(&PlaybackCommand::Pause).is_err());
    }

    #[test]
    fn policy_check_returns_correct_error() {
        let p = PlaybackPolicy::new_readonly();
        let err = p.check_command(&PlaybackCommand::Pause).unwrap_err();
        match err {
            PlaybackValidationError::CommandRestricted { command } => {
                assert_eq!(command, "pause");
            }
            _ => panic!("Expected CommandRestricted"),
        }
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = PlaybackPolicy::new_permissive();
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["allow_play"], true);
        assert_eq!(json["require_approval"], false);
        let back: PlaybackPolicy = serde_json::from_value(json).unwrap();
        assert!(back.allow_play);
        assert!(!back.require_approval);
    }

    #[test]
    fn policy_clone_debug() {
        let p = PlaybackPolicy::new_readonly();
        let cloned = p.clone();
        assert!(!cloned.allow_play);
        let dbg = format!("{p:?}");
        assert!(dbg.contains("PlaybackPolicy"));
    }

    // ── Integration / edge case tests ───────────────────────────

    #[test]
    fn full_playback_flow_play_validate_audit() {
        let policy = PlaybackPolicy::new_permissive();
        let validator = PlaybackCommandValidator::new();

        let cmd = PlaybackCommand::play_context("spotify:playlist:test");
        assert!(policy.check_command(&cmd).is_ok());
        assert!(validator.validate(&cmd).is_ok());

        let evt = PlaybackAuditEvent::allowed(&cmd, Some("dev1".into()), 1000);
        assert!(evt.was_allowed);
        assert_eq!(evt.command, "play");
    }

    #[test]
    fn full_playback_flow_deny_audit() {
        let policy = PlaybackPolicy::new_readonly();
        let cmd = PlaybackCommand::Next;
        let err = policy.check_command(&cmd).unwrap_err();
        let evt = PlaybackAuditEvent::denied(&cmd, None, &err.to_string(), 2000);
        assert!(!evt.was_allowed);
        assert!(evt.details.contains("DENIED"));
    }

    #[test]
    fn validator_and_policy_combined() {
        let mut policy = PlaybackPolicy::new_permissive();
        policy.allow_volume = false;
        let mut validator = PlaybackCommandValidator::new();
        validator.max_volume = 80;

        let cmd = PlaybackCommand::SetVolume { volume_percent: 90 };
        // Policy blocks it first
        assert!(policy.check_command(&cmd).is_err());
        // Validator also blocks it (over max)
        assert!(validator.validate(&cmd).is_err());

        let cmd2 = PlaybackCommand::SetVolume { volume_percent: 70 };
        // Policy still blocks
        assert!(policy.check_command(&cmd2).is_err());
        // But validator allows
        assert!(validator.validate(&cmd2).is_ok());
    }

    #[test]
    fn playback_state_with_full_data() {
        let mut item = PlaybackItem::track("Stairway to Heaven", 482_000);
        item.id = Some("track_xyz".into());
        item.artists = vec!["Led Zeppelin".to_owned()];
        item.album_name = Some("Led Zeppelin IV".into());
        item.uri = Some("spotify:track:track_xyz".into());

        let mut device = Device::new("Living Room Speaker", DeviceType::Speaker);
        device.id = Some("speaker_001".into());
        device.volume_percent = Some(65);
        device.is_active = true;

        let state = PlaybackState {
            is_playing: true,
            progress_ms: Some(120_000),
            device: Some(device),
            item: Some(item),
            shuffle_state: false,
            repeat_state: RepeatMode::Context,
            timestamp: 1_700_000_000_000,
        };

        assert!(state.is_playing);
        assert!(state.has_device());
        assert!(state.has_item());
        let frac = state.progress_fraction().unwrap();
        assert!((frac - 120_000.0 / 482_000.0).abs() < 0.001);
        assert_eq!(state.remaining_ms(), Some(362_000));
        let display = state.to_string();
        assert!(display.contains("Stairway to Heaven"));
        assert!(display.contains("Living Room Speaker"));
    }

    #[test]
    fn device_type_all_variants_in_hashset() {
        let mut set = HashSet::new();
        set.insert(DeviceType::Computer);
        set.insert(DeviceType::Smartphone);
        set.insert(DeviceType::Speaker);
        set.insert(DeviceType::Tv);
        set.insert(DeviceType::GameConsole);
        set.insert(DeviceType::Automobile);
        set.insert(DeviceType::CastVideo);
        set.insert(DeviceType::CastAudio);
        set.insert(DeviceType::Unknown);
        assert_eq!(set.len(), 9);
    }

    #[test]
    fn playback_item_type_all_variants_serde() {
        let types = [
            PlaybackItemType::Track,
            PlaybackItemType::Episode,
            PlaybackItemType::Ad,
            PlaybackItemType::Unknown,
        ];
        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            let back: PlaybackItemType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, t);
        }
    }

    #[test]
    fn command_play_with_offset_only() {
        let cmd = PlaybackCommand::Play {
            context_uri: Some("spotify:album:test".into()),
            offset: Some(0),
            position_ms: None,
        };
        let s = cmd.to_string();
        assert!(s.contains("@0"));
        assert!(!s.contains("pos="));
    }

    #[test]
    fn command_play_with_position_only() {
        let cmd = PlaybackCommand::Play {
            context_uri: None,
            offset: None,
            position_ms: Some(30_000),
        };
        let s = cmd.to_string();
        assert!(s.contains("pos=30000ms"));
    }

    #[test]
    fn validator_boundary_volume_at_max() {
        let mut v = PlaybackCommandValidator::new();
        v.max_volume = 50;
        assert!(
            v.validate(&PlaybackCommand::SetVolume { volume_percent: 50 })
                .is_ok()
        );
        assert!(
            v.validate(&PlaybackCommand::SetVolume { volume_percent: 51 })
                .is_err()
        );
    }

    #[test]
    fn validator_boundary_seek_at_max() {
        let mut v = PlaybackCommandValidator::new();
        v.max_seek_ms = 1000;
        assert!(
            v.validate(&PlaybackCommand::Seek { position_ms: 1000 })
                .is_ok()
        );
        assert!(
            v.validate(&PlaybackCommand::Seek { position_ms: 1001 })
                .is_err()
        );
    }

    #[test]
    fn validator_boundary_seek_at_min() {
        let mut v = PlaybackCommandValidator::new();
        v.min_seek_ms = 100;
        assert!(
            v.validate(&PlaybackCommand::Seek { position_ms: 100 })
                .is_ok()
        );
        assert!(
            v.validate(&PlaybackCommand::Seek { position_ms: 99 })
                .is_err()
        );
    }

    #[test]
    fn policy_require_approval_flag() {
        let mut p = PlaybackPolicy::new_permissive();
        p.require_approval = true;
        assert!(p.require_approval);
        // check_command still allows (approval is tracked, not enforced by check_command)
        assert!(p.check_command(&PlaybackCommand::Pause).is_ok());
    }

    #[test]
    fn device_restricted_flag() {
        let mut d = Device::new("Locked", DeviceType::Tv);
        d.is_restricted = true;
        assert!(d.is_restricted);
    }

    #[test]
    fn device_no_volume_support() {
        let mut d = Device::new("Chromecast", DeviceType::CastAudio);
        d.supports_volume = false;
        assert!(!d.supports_volume);
    }

    #[test]
    fn playback_state_progress_fraction_at_end() {
        let mut state = PlaybackState::idle();
        state.progress_ms = Some(200_000);
        state.item = Some(PlaybackItem::track("Song", 200_000));
        let frac = state.progress_fraction().unwrap();
        assert!((frac - 1.0).abs() < 0.001);
    }

    #[test]
    fn playback_state_progress_fraction_at_start() {
        let mut state = PlaybackState::idle();
        state.progress_ms = Some(0);
        state.item = Some(PlaybackItem::track("Song", 200_000));
        let frac = state.progress_fraction().unwrap();
        assert!((frac - 0.0).abs() < 0.001);
    }

    #[test]
    fn audit_event_for_all_commands() {
        let commands = [
            PlaybackCommand::resume(),
            PlaybackCommand::Pause,
            PlaybackCommand::Next,
            PlaybackCommand::Previous,
            PlaybackCommand::Seek {
                position_ms: 10_000,
            },
            PlaybackCommand::SetVolume { volume_percent: 50 },
            PlaybackCommand::SetShuffle { state: true },
            PlaybackCommand::SetRepeat {
                mode: RepeatMode::Track,
            },
            PlaybackCommand::TransferPlayback {
                device_id: "d1".into(),
                play: false,
            },
        ];
        for cmd in &commands {
            let evt = PlaybackAuditEvent::allowed(cmd, None, 0);
            assert!(evt.was_allowed);
            assert_eq!(evt.command, cmd.name());
        }
    }

    #[test]
    fn validator_play_none_context_uri_is_ok() {
        let v = PlaybackCommandValidator::new();
        let cmd = PlaybackCommand::resume();
        assert!(v.validate(&cmd).is_ok());
    }

    #[test]
    fn validator_shuffle_always_valid() {
        let v = PlaybackCommandValidator::new();
        assert!(
            v.validate(&PlaybackCommand::SetShuffle { state: true })
                .is_ok()
        );
        assert!(
            v.validate(&PlaybackCommand::SetShuffle { state: false })
                .is_ok()
        );
    }

    #[test]
    fn validator_repeat_always_valid() {
        let v = PlaybackCommandValidator::new();
        for mode in [RepeatMode::Off, RepeatMode::Track, RepeatMode::Context] {
            assert!(v.validate(&PlaybackCommand::SetRepeat { mode }).is_ok());
        }
    }

    #[test]
    fn validator_next_previous_always_valid() {
        let v = PlaybackCommandValidator::new();
        assert!(v.validate(&PlaybackCommand::Next).is_ok());
        assert!(v.validate(&PlaybackCommand::Previous).is_ok());
    }

    #[test]
    fn device_serde_all_device_types() {
        let types = [
            DeviceType::Computer,
            DeviceType::Smartphone,
            DeviceType::Speaker,
            DeviceType::Tv,
            DeviceType::GameConsole,
            DeviceType::Automobile,
            DeviceType::CastVideo,
            DeviceType::CastAudio,
            DeviceType::Unknown,
        ];
        for dt in types {
            let d = Device::new("Test", dt);
            let json = serde_json::to_value(&d).unwrap();
            let back: Device = serde_json::from_value(json).unwrap();
            assert_eq!(back.device_type, dt);
        }
    }

    #[test]
    fn policy_selective_permissions() {
        let mut p = PlaybackPolicy::new_readonly();
        p.allow_seek = true;
        p.allow_volume = true;
        assert_eq!(p.allowed_count(), 2);
        assert!(
            p.check_command(&PlaybackCommand::Seek { position_ms: 100 })
                .is_ok()
        );
        assert!(
            p.check_command(&PlaybackCommand::SetVolume { volume_percent: 50 })
                .is_ok()
        );
        assert!(p.check_command(&PlaybackCommand::Pause).is_err());
        assert!(p.check_command(&PlaybackCommand::Next).is_err());
    }
}
