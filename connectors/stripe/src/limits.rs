//! Stripe platform limits used by validation and boundary tests.

/// Maximum webhook payload size in bytes (256 KiB).
pub const MAX_WEBHOOK_PAYLOAD_BYTES: usize = 256 * 1024;
/// Maximum webhook replay cache entries before eviction.
pub const MAX_WEBHOOK_REPLAY_ENTRIES: usize = 4096;
/// Maximum characters in a metadata key.
pub const METADATA_KEY_MAX_CHARS: usize = 40;
/// Maximum characters in a metadata value.
pub const METADATA_VALUE_MAX_CHARS: usize = 500;
/// Maximum metadata key-value pairs per object.
pub const METADATA_MAX_PAIRS: usize = 50;
