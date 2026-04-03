//! Discord API platform limits for validation and boundary tests.
//!
//! Values sourced from the Discord Developer Documentation.

// ── Message Content ─────────────────────────────────────────────────────

/// Maximum characters allowed in message content.
pub const MESSAGE_CONTENT_MAX_CHARS: usize = 2_000;
/// Maximum characters allowed in a thread name.
pub const THREAD_NAME_MAX_CHARS: usize = 100;

// ── Embeds ──────────────────────────────────────────────────────────────

/// Maximum embeds allowed in a single message.
pub const EMBEDS_MAX_COUNT: usize = 10;
/// Maximum combined characters allowed across all embeds in one message.
pub const EMBED_TOTAL_MAX_CHARS: usize = 6_000;
/// Maximum characters allowed in an embed title.
pub const EMBED_TITLE_MAX_CHARS: usize = 256;
/// Maximum characters allowed in an embed description.
pub const EMBED_DESCRIPTION_MAX_CHARS: usize = 4_096;
/// Maximum fields in a single embed.
pub const EMBED_FIELDS_MAX_COUNT: usize = 25;
/// Maximum characters in an embed field name.
pub const EMBED_FIELD_NAME_MAX_CHARS: usize = 256;
/// Maximum characters in an embed field value.
pub const EMBED_FIELD_VALUE_MAX_CHARS: usize = 1_024;
/// Maximum characters in an embed footer text.
pub const EMBED_FOOTER_MAX_CHARS: usize = 2_048;
/// Maximum characters in an embed author name.
pub const EMBED_AUTHOR_NAME_MAX_CHARS: usize = 256;

// ── Attachments ─────────────────────────────────────────────────────────

/// Maximum number of attachments per message.
pub const ATTACHMENTS_MAX_COUNT: usize = 10;
/// Maximum file size for uploads (non-boosted server, bytes). 25 MB.
pub const ATTACHMENT_MAX_BYTES: u64 = 25 * 1024 * 1024;
/// Maximum file size for uploads (boost level 2, bytes). 50 MB.
pub const ATTACHMENT_MAX_BYTES_BOOST_2: u64 = 50 * 1024 * 1024;
/// Maximum file size for uploads (boost level 3, bytes). 100 MB.
pub const ATTACHMENT_MAX_BYTES_BOOST_3: u64 = 100 * 1024 * 1024;

// ── Components (Buttons, Selects, Modals) ───────────────────────────────

/// Maximum action rows per message.
pub const ACTION_ROWS_MAX_COUNT: usize = 5;
/// Maximum buttons per action row.
pub const BUTTONS_PER_ROW_MAX: usize = 5;
/// Maximum select menu options.
pub const SELECT_OPTIONS_MAX: usize = 25;
/// Maximum characters in a button label.
pub const BUTTON_LABEL_MAX_CHARS: usize = 80;
/// Maximum characters in a `custom_id` for components.
pub const CUSTOM_ID_MAX_CHARS: usize = 100;
/// Maximum characters in a select menu placeholder.
pub const SELECT_PLACEHOLDER_MAX_CHARS: usize = 150;
/// Maximum characters in a modal title.
pub const MODAL_TITLE_MAX_CHARS: usize = 45;
/// Maximum text input components per modal.
pub const MODAL_COMPONENTS_MAX: usize = 5;
/// Maximum characters in a text input label.
pub const TEXT_INPUT_LABEL_MAX_CHARS: usize = 45;
/// Maximum characters in a short text input value.
pub const TEXT_INPUT_SHORT_MAX_CHARS: usize = 4_000;
/// Maximum characters in a paragraph text input value.
pub const TEXT_INPUT_PARAGRAPH_MAX_CHARS: usize = 4_000;

// ── Stickers ────────────────────────────────────────────────────────────

/// Maximum stickers per message.
pub const STICKERS_MAX_COUNT: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_limits_within_discord_spec() {
        assert_eq!(MESSAGE_CONTENT_MAX_CHARS, 2000);
        assert_eq!(THREAD_NAME_MAX_CHARS, 100);
    }

    #[test]
    fn embed_limits_within_discord_spec() {
        assert_eq!(EMBEDS_MAX_COUNT, 10);
        assert!(EMBED_TOTAL_MAX_CHARS >= EMBED_DESCRIPTION_MAX_CHARS);
        assert_eq!(EMBED_FIELDS_MAX_COUNT, 25);
    }

    #[test]
    fn attachment_limits_ordered() {
        assert!(ATTACHMENT_MAX_BYTES < ATTACHMENT_MAX_BYTES_BOOST_2);
        assert!(ATTACHMENT_MAX_BYTES_BOOST_2 < ATTACHMENT_MAX_BYTES_BOOST_3);
        assert_eq!(ATTACHMENTS_MAX_COUNT, 10);
    }

    #[test]
    fn component_limits_within_discord_spec() {
        assert_eq!(ACTION_ROWS_MAX_COUNT, 5);
        assert_eq!(BUTTONS_PER_ROW_MAX, 5);
        assert_eq!(SELECT_OPTIONS_MAX, 25);
        assert!(CUSTOM_ID_MAX_CHARS <= 100);
    }

    #[test]
    fn modal_limits_within_discord_spec() {
        assert_eq!(MODAL_COMPONENTS_MAX, 5);
        assert!(MODAL_TITLE_MAX_CHARS <= 45);
        assert!(TEXT_INPUT_LABEL_MAX_CHARS <= 45);
    }
}
