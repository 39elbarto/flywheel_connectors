//! Telegram Bot API platform limits for validation and boundary tests.
//!
//! Values sourced from the Telegram Bot API documentation.

// ── Text & Caption ──────────────────────────────────────────────────────

/// Maximum characters allowed in message text (sendMessage).
pub const MESSAGE_TEXT_MAX_CHARS: usize = 4_096;
/// Maximum characters allowed in media captions (photo, video, document, etc.).
pub const MEDIA_CAPTION_MAX_CHARS: usize = 1_024;

// ── Callback Data ───────────────────────────────────────────────────────

/// Maximum bytes in `callback_data` for inline keyboard buttons.
/// Telegram enforces 1-64 bytes per callback_data payload.
pub const CALLBACK_DATA_MAX_BYTES: usize = 64;
/// Maximum bytes allowed in `answer_callback_query` text notification.
pub const CALLBACK_ANSWER_TEXT_MAX_CHARS: usize = 200;
/// Maximum bytes allowed in `answer_callback_query` URL.
pub const CALLBACK_ANSWER_URL_MAX_CHARS: usize = 256;

// ── Media Groups ────────────────────────────────────────────────────────

/// Minimum items in a media group (sendMediaGroup).
pub const MEDIA_GROUP_MIN_ITEMS: usize = 2;
/// Maximum items in a media group (sendMediaGroup).
pub const MEDIA_GROUP_MAX_ITEMS: usize = 10;

// ── File Uploads ────────────────────────────────────────────────────────

/// Maximum file size for photo uploads via multipart (bytes).
/// Telegram limit: 10 MB for photos.
pub const PHOTO_UPLOAD_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Maximum file size for other file uploads via Bot API (bytes).
/// Telegram limit: 50 MB for documents, audio, video via multipart.
pub const FILE_UPLOAD_MAX_BYTES: u64 = 50 * 1024 * 1024;
/// Maximum file size for downloads via `getFile` (bytes).
/// Telegram limit: 20 MB for file downloads.
pub const FILE_DOWNLOAD_MAX_BYTES: u64 = 20 * 1024 * 1024;

// ── Inline Keyboard ─────────────────────────────────────────────────────

/// Maximum inline keyboard buttons per row (practical limit).
pub const INLINE_KEYBOARD_MAX_BUTTONS_PER_ROW: usize = 8;
/// Maximum inline keyboard rows (practical limit).
pub const INLINE_KEYBOARD_MAX_ROWS: usize = 100;

// ── Polling ─────────────────────────────────────────────────────────────

/// Maximum `timeout` seconds for `getUpdates` long polling.
pub const LONG_POLL_MAX_TIMEOUT_SECS: u64 = 50;
/// Maximum number of updates returned per `getUpdates` call.
pub const GET_UPDATES_MAX_LIMIT: u32 = 100;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_limits_within_telegram_spec() {
        assert_eq!(MESSAGE_TEXT_MAX_CHARS, 4096);
        assert_eq!(MEDIA_CAPTION_MAX_CHARS, 1024);
    }

    #[test]
    fn callback_limits_within_telegram_spec() {
        assert_eq!(CALLBACK_DATA_MAX_BYTES, 64);
        assert!(CALLBACK_ANSWER_TEXT_MAX_CHARS <= 200);
    }

    #[test]
    fn media_group_bounds() {
        assert!(MEDIA_GROUP_MIN_ITEMS >= 2);
        assert!(MEDIA_GROUP_MAX_ITEMS <= 10);
        assert!(MEDIA_GROUP_MIN_ITEMS <= MEDIA_GROUP_MAX_ITEMS);
    }

    #[test]
    fn upload_limits_ordered() {
        assert!(PHOTO_UPLOAD_MAX_BYTES < FILE_UPLOAD_MAX_BYTES);
        assert!(FILE_DOWNLOAD_MAX_BYTES < FILE_UPLOAD_MAX_BYTES);
    }

    #[test]
    fn polling_limits_reasonable() {
        assert!(LONG_POLL_MAX_TIMEOUT_SECS <= 60);
        assert!(GET_UPDATES_MAX_LIMIT <= 100);
    }
}
