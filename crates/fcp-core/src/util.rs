//! Utility modules for FCP Core.

use std::{error::Error, fmt, str::FromStr, time::Duration};

pub mod base64_url;
pub mod hex_or_bytes;
pub mod hex_or_bytes_vec;
pub mod hostname;
pub mod objectid_prefixed;
pub mod uri;

pub use uri::SafeUri;

/// Convert an ASCII label to kebab-case.
#[must_use]
pub fn to_kebab_case(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut previous_kind = None;
    let mut pending_separator = false;
    let mut chars = input.trim().chars().peekable();

    while let Some(ch) = chars.next() {
        if ch.is_ascii_alphanumeric() {
            let kind = KebabCharKind::from_ascii_alphanumeric(ch);
            let next_is_lowercase = chars.peek().is_some_and(|next| next.is_ascii_lowercase());
            let camel_boundary = matches!(
                (previous_kind, kind),
                (Some(KebabCharKind::Lower | KebabCharKind::Digit | KebabCharKind::Upper), KebabCharKind::Upper)
                    if next_is_lowercase
            );

            if (pending_separator || camel_boundary) && !output.is_empty() {
                output.push('-');
            }

            output.push(ch.to_ascii_lowercase());
            previous_kind = Some(kind);
            pending_separator = false;
        } else {
            pending_separator = true;
            previous_kind = None;
        }
    }

    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KebabCharKind {
    Lower,
    Upper,
    Digit,
}

impl KebabCharKind {
    fn from_ascii_alphanumeric(ch: char) -> Self {
        if ch.is_ascii_digit() {
            Self::Digit
        } else if ch.is_ascii_uppercase() {
            Self::Upper
        } else {
            Self::Lower
        }
    }
}

/// Maximum accepted canonical duration.
pub const MAX_CANONICAL_DURATION: Duration = Duration::from_secs(86_400);

/// Millisecond-granular duration with deterministic text representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalDuration(Duration);

impl CanonicalDuration {
    /// Construct a canonical duration if it is representable and within bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when `duration` exceeds [`MAX_CANONICAL_DURATION`] or
    /// carries sub-millisecond precision.
    pub fn new(duration: Duration) -> Result<Self, CanonicalDurationParseError> {
        if duration.subsec_nanos() % 1_000_000 != 0 {
            return Err(CanonicalDurationParseError::SubMillisecondPrecision);
        }

        let millis = duration.as_millis();
        let max_millis = MAX_CANONICAL_DURATION.as_millis();
        if millis > max_millis {
            return Err(CanonicalDurationParseError::ExceedsMaximum { millis, max_millis });
        }

        Ok(Self(duration))
    }

    /// Return the wrapped [`Duration`].
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        self.0
    }
}

impl TryFrom<Duration> for CanonicalDuration {
    type Error = CanonicalDurationParseError;

    fn try_from(value: Duration) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<CanonicalDuration> for Duration {
    fn from(value: CanonicalDuration) -> Self {
        value.0
    }
}

impl FromStr for CanonicalDuration {
    type Err = CanonicalDurationParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        if input.is_empty() {
            return Err(CanonicalDurationParseError::Empty);
        }

        let (number, unit) = if let Some(number) = input.strip_suffix("ms") {
            (number, DurationUnit::Milliseconds)
        } else if let Some(number) = input.strip_suffix('s') {
            (number, DurationUnit::Seconds)
        } else {
            return Err(CanonicalDurationParseError::MissingUnit);
        };

        if number.is_empty() || !number.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(CanonicalDurationParseError::InvalidNumber);
        }

        let value = number
            .parse::<u128>()
            .map_err(|_| CanonicalDurationParseError::InvalidNumber)?;
        let millis = match unit {
            DurationUnit::Milliseconds => value,
            DurationUnit::Seconds => {
                value
                    .checked_mul(1_000)
                    .ok_or(CanonicalDurationParseError::ExceedsMaximum {
                        millis: u128::MAX,
                        max_millis: MAX_CANONICAL_DURATION.as_millis(),
                    })?
            }
        };
        let max_millis = MAX_CANONICAL_DURATION.as_millis();
        if millis > max_millis {
            return Err(CanonicalDurationParseError::ExceedsMaximum { millis, max_millis });
        }

        let millis = u64::try_from(millis)
            .map_err(|_| CanonicalDurationParseError::ExceedsMaximum { millis, max_millis })?;
        Self::new(Duration::from_millis(millis))
    }
}

impl fmt::Display for CanonicalDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let millis = self.0.as_millis();
        if millis == 0 {
            write!(f, "0s")
        } else if millis % 1_000 == 0 {
            write!(f, "{}s", millis / 1_000)
        } else {
            write!(f, "{millis}ms")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurationUnit {
    Milliseconds,
    Seconds,
}

/// Error returned when parsing or constructing [`CanonicalDuration`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalDurationParseError {
    /// Input is empty after trimming.
    Empty,
    /// Input has no supported unit suffix.
    MissingUnit,
    /// Input has an empty or non-decimal numeric component.
    InvalidNumber,
    /// Input duration exceeds [`MAX_CANONICAL_DURATION`].
    ExceedsMaximum {
        /// Parsed duration in milliseconds.
        millis: u128,
        /// Maximum allowed duration in milliseconds.
        max_millis: u128,
    },
    /// Duration cannot be represented in canonical millisecond precision.
    SubMillisecondPrecision,
}

impl fmt::Display for CanonicalDurationParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "duration is empty"),
            Self::MissingUnit => write!(f, "duration must use an 'ms' or 's' suffix"),
            Self::InvalidNumber => write!(f, "duration value must be an unsigned decimal integer"),
            Self::ExceedsMaximum { millis, max_millis } => write!(
                f,
                "duration {millis}ms exceeds configured maximum {max_millis}ms"
            ),
            Self::SubMillisecondPrecision => {
                write!(f, "duration must be representable in whole milliseconds")
            }
        }
    }
}

impl Error for CanonicalDurationParseError {}

/// Second-granular relative time using compact `s`, `m`, `h`, `d`, or `w` units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelativeTime(Duration);

impl RelativeTime {
    /// Construct relative time when it can be represented with whole seconds.
    ///
    /// # Errors
    ///
    /// Returns an error when `duration` carries sub-second precision.
    pub fn new(duration: Duration) -> Result<Self, RelativeTimeParseError> {
        if duration.subsec_nanos() != 0 {
            return Err(RelativeTimeParseError::SubsecondPrecision);
        }

        Ok(Self(duration))
    }

    /// Return the wrapped [`Duration`].
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        self.0
    }
}

impl TryFrom<Duration> for RelativeTime {
    type Error = RelativeTimeParseError;

    fn try_from(value: Duration) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RelativeTime> for Duration {
    fn from(value: RelativeTime) -> Self {
        value.0
    }
}

impl FromStr for RelativeTime {
    type Err = RelativeTimeParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        if input.is_empty() {
            return Err(RelativeTimeParseError::Empty);
        }

        let (number, seconds_per_unit) =
            RelativeTimeUnit::parse(input).ok_or(RelativeTimeParseError::MissingUnit)?;
        if number.is_empty() || !number.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(RelativeTimeParseError::InvalidNumber);
        }

        let value = number
            .parse::<u64>()
            .map_err(|_| RelativeTimeParseError::InvalidNumber)?;
        let seconds = value
            .checked_mul(seconds_per_unit)
            .ok_or(RelativeTimeParseError::Overflow)?;

        Ok(Self(Duration::from_secs(seconds)))
    }
}

impl fmt::Display for RelativeTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.0.as_secs();
        for unit in RelativeTimeUnit::DISPLAY_ORDER {
            if seconds != 0 && seconds % unit.seconds == 0 {
                return write!(f, "{}{}", seconds / unit.seconds, unit.suffix);
            }
        }

        write!(f, "{seconds}s")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelativeTimeUnit {
    suffix: &'static str,
    seconds: u64,
}

impl RelativeTimeUnit {
    const DISPLAY_ORDER: [Self; 5] = [
        Self::WEEKS,
        Self::DAYS,
        Self::HOURS,
        Self::MINUTES,
        Self::SECONDS,
    ];

    const SECONDS: Self = Self {
        suffix: "s",
        seconds: 1,
    };
    const MINUTES: Self = Self {
        suffix: "m",
        seconds: 60,
    };
    const HOURS: Self = Self {
        suffix: "h",
        seconds: 60 * 60,
    };
    const DAYS: Self = Self {
        suffix: "d",
        seconds: 24 * 60 * 60,
    };
    const WEEKS: Self = Self {
        suffix: "w",
        seconds: 7 * 24 * 60 * 60,
    };

    fn parse(input: &str) -> Option<(&str, u64)> {
        for unit in [
            Self::SECONDS,
            Self::MINUTES,
            Self::HOURS,
            Self::DAYS,
            Self::WEEKS,
        ] {
            if let Some(number) = input.strip_suffix(unit.suffix) {
                return Some((number, unit.seconds));
            }
        }

        None
    }
}

/// Error returned when parsing or constructing [`RelativeTime`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelativeTimeParseError {
    /// Input is empty after trimming.
    Empty,
    /// Input has no supported relative-time unit suffix.
    MissingUnit,
    /// Input has an empty or non-decimal numeric component.
    InvalidNumber,
    /// Parsed relative time overflowed `u64` seconds.
    Overflow,
    /// Duration cannot be represented in whole seconds.
    SubsecondPrecision,
}

impl fmt::Display for RelativeTimeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "relative time is empty"),
            Self::MissingUnit => {
                write!(
                    f,
                    "relative time must use an 's', 'm', 'h', 'd', or 'w' suffix"
                )
            }
            Self::InvalidNumber => {
                write!(f, "relative time value must be an unsigned decimal integer")
            }
            Self::Overflow => write!(f, "relative time exceeds u64::MAX seconds"),
            Self::SubsecondPrecision => write!(f, "relative time must use whole seconds"),
        }
    }
}

impl Error for RelativeTimeParseError {}

/// Byte count with deterministic binary-unit text representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSize(u64);

impl ByteSize {
    /// Construct a byte-size wrapper from a raw byte count.
    #[must_use]
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Return the wrapped byte count.
    #[must_use]
    pub const fn as_bytes(self) -> u64 {
        self.0
    }
}

impl From<u64> for ByteSize {
    fn from(value: u64) -> Self {
        Self::from_bytes(value)
    }
}

impl From<ByteSize> for u64 {
    fn from(value: ByteSize) -> Self {
        value.0
    }
}

impl FromStr for ByteSize {
    type Err = ByteSizeParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        if input.is_empty() {
            return Err(ByteSizeParseError::Empty);
        }

        let (number, multiplier) = if let Some(number) = input.strip_suffix("GiB") {
            (number, 1024_u64.pow(3))
        } else if let Some(number) = input.strip_suffix("MiB") {
            (number, 1024_u64.pow(2))
        } else if let Some(number) = input.strip_suffix("KiB") {
            (number, 1024_u64)
        } else if let Some(number) = input.strip_suffix('B') {
            (number, 1)
        } else {
            return Err(ByteSizeParseError::MissingUnit);
        };

        if number.is_empty() || !number.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(ByteSizeParseError::InvalidNumber);
        }

        let value = number
            .parse::<u64>()
            .map_err(|_| ByteSizeParseError::InvalidNumber)?;
        let bytes = value
            .checked_mul(multiplier)
            .ok_or(ByteSizeParseError::Overflow)?;

        Ok(Self(bytes))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const KIB: u64 = 1024;
        const MIB: u64 = KIB * 1024;
        const GIB: u64 = MIB * 1024;

        let bytes = self.0;
        if bytes != 0 && bytes % GIB == 0 {
            write!(f, "{}GiB", bytes / GIB)
        } else if bytes != 0 && bytes % MIB == 0 {
            write!(f, "{}MiB", bytes / MIB)
        } else if bytes != 0 && bytes % KIB == 0 {
            write!(f, "{}KiB", bytes / KIB)
        } else {
            write!(f, "{bytes}B")
        }
    }
}

/// Error returned when parsing [`ByteSize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteSizeParseError {
    /// Input is empty after trimming.
    Empty,
    /// Input has no supported binary byte-size unit suffix.
    MissingUnit,
    /// Input has an empty or non-decimal numeric component.
    InvalidNumber,
    /// Parsed byte count overflowed `u64`.
    Overflow,
}

impl fmt::Display for ByteSizeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "byte size is empty"),
            Self::MissingUnit => {
                write!(f, "byte size must use a 'B', 'KiB', 'MiB', or 'GiB' suffix")
            }
            Self::InvalidNumber => {
                write!(f, "byte size value must be an unsigned decimal integer")
            }
            Self::Overflow => write!(f, "byte size exceeds u64::MAX bytes"),
        }
    }
}

impl Error for ByteSizeParseError {}
