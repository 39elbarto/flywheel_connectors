//! Utility modules for FCP Core.

use std::{error::Error, fmt, str::FromStr, time::Duration};

pub mod hex_or_bytes;
pub mod hex_or_bytes_vec;
pub mod objectid_prefixed;

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
