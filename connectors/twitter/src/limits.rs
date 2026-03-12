//! Twitter/X platform limits used by validation and boundary tests.

/// Maximum characters allowed in a tweet.
pub const TWEET_TEXT_MAX_CHARS: usize = 280;
/// Maximum characters allowed in a direct message.
pub const DM_TEXT_MAX_CHARS: usize = 10_000;
/// Maximum tweet IDs per batch lookup.
pub const TWEET_IDS_BATCH_MAX: usize = 100;
/// Maximum results per search request.
pub const SEARCH_MAX_RESULTS: usize = 100;
/// Maximum results per timeline request.
pub const TIMELINE_MAX_RESULTS: usize = 100;
/// Maximum results per DM list request.
pub const DM_LIST_MAX_RESULTS: usize = 100;
