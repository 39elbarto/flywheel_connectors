//! Telegram platform limits used by validation and boundary tests.
//!
//! TODO: Add callback-data, media-group, and upload-size limits when those
//! operations are implemented.

/// Maximum characters allowed in message text.
pub const MESSAGE_TEXT_MAX_CHARS: usize = 4_096;
/// Maximum characters allowed in media captions.
pub const MEDIA_CAPTION_MAX_CHARS: usize = 1_024;
