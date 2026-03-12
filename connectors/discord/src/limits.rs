//! Discord platform limits used by validation and boundary tests.
//!
//! TODO: Add attachment count/size and component payload limits when those
//! operations are implemented.

/// Maximum characters allowed in message content.
pub const MESSAGE_CONTENT_MAX_CHARS: usize = 2_000;
/// Maximum embeds allowed in a single message.
pub const EMBEDS_MAX_COUNT: usize = 10;
/// Maximum combined characters allowed across all embeds in one message.
pub const EMBED_TOTAL_MAX_CHARS: usize = 6_000;
/// Maximum characters allowed in an embed title.
pub const EMBED_TITLE_MAX_CHARS: usize = 256;
/// Maximum characters allowed in an embed description.
pub const EMBED_DESCRIPTION_MAX_CHARS: usize = 4_096;
/// Maximum characters allowed in a thread name.
pub const THREAD_NAME_MAX_CHARS: usize = 100;
