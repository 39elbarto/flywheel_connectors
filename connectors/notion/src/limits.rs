//! Notion platform limits used by validation and boundary tests.

/// Maximum block children allowed per append request.
pub const BLOCKS_MAX_PER_REQUEST: usize = 100;
/// Maximum characters allowed in a page title.
pub const PAGE_TITLE_MAX_CHARS: usize = 2_000;
/// Maximum characters allowed in a rich text block.
pub const RICH_TEXT_MAX_CHARS: usize = 2_000;
