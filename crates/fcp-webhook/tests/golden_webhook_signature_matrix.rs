//! Golden vector for the webhook signature verification matrix.
//!
//! `e2e_webhook_signatures.rs` and `e2e_webhook_delivery_retry.rs`
//! cover behavioral round-trips. `webhook_receiver_compliance.rs`
//! covers per-provider compliance. None of those tests freeze the
//! *outcome shape* operators read off the receiver decision: which
//! `WebhookError` variant fires for each (provider × signature
//! correctness × timestamp window × replay state) cell.
//!
//! This golden walks 12 cells across the three first-class
//! providers (GitHub, Stripe, Slack) and freezes the verdict for
//! each. A regression that changes "`InvalidSignature`" → "`BadSignature`",
//! or that swaps which path fires first when both signature and
//! timestamp are wrong, surfaces here as a per-row diff.
//!
//! Cells:
//!
//!   - GitHub: valid first-attempt, replay, wrong-signature
//!   - Stripe: valid current, stale (-600s), future (+600s),
//!     replay, wrong-signature
//!   - Slack: valid current, stale, replay, wrong-signature
//!
//! Determinism: signatures are HMAC-SHA256 (deterministic from
//! secret + body); replay cache uses `InMemoryReplayCache`. The only
//! moving part is wall-clock; we offset relative to `Utc::now()` so
//! cells fall in a stable bucket regardless of when the test runs.
//! Stale (-600s) and future (+600s) both fall outside the default
//! 300s tolerance window, so their classification is stable.

use std::collections::HashMap;

use chrono::Utc;
use fcp_webhook::{
    GitHubWebhook, HmacSha256Verifier, SlackWebhook, StripeWebhook, WebhookError, WebhookHandler,
};

const GITHUB_SECRET: &str = "github_golden_signature_matrix_secret_2026";
const STRIPE_SECRET: &str = "whsec_golden_signature_matrix_secret_2026";
const SLACK_SECRET: &str = "slack_golden_signature_matrix_secret_2026";
const WRONG_SECRET: &str = "wrong_secret_used_to_sign_an_attacker_forgery";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    GitHub,
    Stripe,
    Slack,
}

impl Provider {
    const fn label(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::Stripe => "stripe",
            Self::Slack => "slack",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SignatureSource {
    /// Signed with the provider's correct secret.
    Correct,
    /// Signed with `WRONG_SECRET` — verifier holds the correct secret.
    WrongSecret,
}

#[derive(Debug, Clone, Copy)]
enum TimestampOffset {
    /// Within the tolerance window (we use 0).
    Current,
    /// Stale: -600s, well outside the 300s default tolerance.
    Stale,
    /// Future: +600s, well outside the 300s default tolerance.
    Future,
    /// No timestamp validation (GitHub doesn't carry one).
    NotApplicable,
}

#[derive(Debug, Clone, Copy)]
enum ReplayState {
    /// First time this event id is seen.
    First,
    /// Same event id replayed.
    Replay,
}

#[derive(Debug, Clone)]
struct Cell {
    label: &'static str,
    provider: Provider,
    signature: SignatureSource,
    timestamp: TimestampOffset,
    replay: ReplayState,
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accepted,
    InvalidSignature,
    TimestampOutOfWindow,
    Replay,
    Other(String),
}

impl Verdict {
    fn label(&self) -> String {
        match self {
            Self::Accepted => "Accepted".to_string(),
            Self::InvalidSignature => "InvalidSignature".to_string(),
            Self::TimestampOutOfWindow => "TimestampOutOfWindow".to_string(),
            Self::Replay => "Replay".to_string(),
            Self::Other(msg) => format!("Other({msg})"),
        }
    }
}

fn map_error(err: &WebhookError) -> Verdict {
    match err {
        WebhookError::InvalidSignature | WebhookError::MissingSignature(_) => {
            Verdict::InvalidSignature
        }
        WebhookError::TimestampValidation { .. } => Verdict::TimestampOutOfWindow,
        WebhookError::ReplayDetected { .. } => Verdict::Replay,
        other => Verdict::Other(format!("{other:?}")),
    }
}

fn github_cell(
    cell: &Cell,
    receiver: &GitHubWebhook,
    replay_handler: &WebhookHandler<HmacSha256Verifier>,
) -> Verdict {
    let body = br#"{"ref":"refs/heads/main","commits":[]}"#;
    let secret = match cell.signature {
        SignatureSource::Correct => GITHUB_SECRET,
        SignatureSource::WrongSecret => WRONG_SECRET,
    };
    let sig = HmacSha256Verifier::new(secret).compute(body);
    let mut headers = HashMap::new();
    headers.insert("X-Hub-Signature-256".to_string(), format!("sha256={sig}"));
    headers.insert("X-GitHub-Event".to_string(), "push".to_string());
    let event_id = match cell.replay {
        ReplayState::First => format!("delivery-{}-first", cell.label),
        ReplayState::Replay => format!("delivery-replayed-{}", cell.label),
    };
    headers.insert("X-GitHub-Delivery".to_string(), event_id.clone());

    // First parse — captures signature failure if applicable.
    let parsed = receiver.verify_and_parse(&headers, body);

    // Replay check: pre-claim if cell is `Replay` so the second
    // claim_event surfaces ReplayDetected.
    if matches!(cell.replay, ReplayState::Replay) {
        let _ = replay_handler.claim_event(&event_id);
    }

    match parsed {
        Ok(event) => {
            // Apply replay claim.
            match replay_handler.claim_event(&event.id) {
                Ok(()) => Verdict::Accepted,
                Err(e) => map_error(&e),
            }
        }
        Err(e) => map_error(&e),
    }
}

fn stripe_cell(
    cell: &Cell,
    receiver: &StripeWebhook,
    replay_handler: &WebhookHandler<HmacSha256Verifier>,
) -> Verdict {
    let body = format!(
        r#"{{"id":"evt_golden_{label}","type":"payment_intent.succeeded","data":{{"object":{{}}}}}}"#,
        label = cell.label
    );
    let body_bytes = body.as_bytes();
    let now = Utc::now().timestamp();
    let timestamp = match cell.timestamp {
        TimestampOffset::Current | TimestampOffset::NotApplicable => now,
        TimestampOffset::Stale => now - 600,
        TimestampOffset::Future => now + 600,
    };
    let secret = match cell.signature {
        SignatureSource::Correct => STRIPE_SECRET,
        SignatureSource::WrongSecret => WRONG_SECRET,
    };
    let signed_payload = format!("{timestamp}.{body}");
    let sig = HmacSha256Verifier::new(secret).compute(signed_payload.as_bytes());
    let mut headers = HashMap::new();
    headers.insert(
        "Stripe-Signature".to_string(),
        format!("t={timestamp},v1={sig}"),
    );

    let parsed = receiver.verify_and_parse(&headers, body_bytes);

    // For replay scenario, pre-claim the canonical event id BEFORE
    // we run the parsed-then-claim path so the test cell's claim
    // returns Replay.
    let canonical_event_id = format!("evt_golden_{}", cell.label);
    if matches!(cell.replay, ReplayState::Replay) {
        let _ = replay_handler.claim_event(&canonical_event_id);
    }

    match parsed {
        Ok(event) => match replay_handler.claim_event(&event.id) {
            Ok(()) => Verdict::Accepted,
            Err(e) => map_error(&e),
        },
        Err(e) => map_error(&e),
    }
}

fn slack_cell(
    cell: &Cell,
    receiver: &SlackWebhook,
    replay_handler: &WebhookHandler<HmacSha256Verifier>,
) -> Verdict {
    let body = format!(
        r#"{{"type":"event_callback","event":{{"type":"message"}},"event_id":"EvGolden{label}"}}"#,
        label = cell.label.replace('-', "_")
    );
    let body_bytes = body.as_bytes();
    let now = Utc::now().timestamp();
    let timestamp = match cell.timestamp {
        TimestampOffset::Current | TimestampOffset::NotApplicable => now,
        TimestampOffset::Stale => now - 600,
        TimestampOffset::Future => now + 600,
    };
    let secret = match cell.signature {
        SignatureSource::Correct => SLACK_SECRET,
        SignatureSource::WrongSecret => WRONG_SECRET,
    };
    let signed_payload = format!("v0:{timestamp}:{body}");
    let sig = HmacSha256Verifier::new(secret).compute(signed_payload.as_bytes());
    let mut headers = HashMap::new();
    headers.insert("X-Slack-Signature".to_string(), format!("v0={sig}"));
    headers.insert(
        "X-Slack-Request-Timestamp".to_string(),
        timestamp.to_string(),
    );

    let parsed = receiver.verify_and_parse(&headers, body_bytes);

    let canonical_event_id = format!("EvGolden{}", cell.label.replace('-', "_"));
    if matches!(cell.replay, ReplayState::Replay) {
        let _ = replay_handler.claim_event(&canonical_event_id);
    }

    match parsed {
        Ok(event) => match replay_handler.claim_event(&event.id) {
            Ok(()) => Verdict::Accepted,
            Err(e) => map_error(&e),
        },
        Err(e) => map_error(&e),
    }
}

#[allow(clippy::too_many_lines)]
fn render_golden() -> String {
    let cells = vec![
        // GitHub: no timestamp window, just signature + replay.
        Cell {
            label: "github_valid_first",
            provider: Provider::GitHub,
            signature: SignatureSource::Correct,
            timestamp: TimestampOffset::NotApplicable,
            replay: ReplayState::First,
        },
        Cell {
            label: "github_valid_replayed",
            provider: Provider::GitHub,
            signature: SignatureSource::Correct,
            timestamp: TimestampOffset::NotApplicable,
            replay: ReplayState::Replay,
        },
        Cell {
            label: "github_wrong_signature",
            provider: Provider::GitHub,
            signature: SignatureSource::WrongSecret,
            timestamp: TimestampOffset::NotApplicable,
            replay: ReplayState::First,
        },
        // Stripe: full matrix.
        Cell {
            label: "stripe_valid_current",
            provider: Provider::Stripe,
            signature: SignatureSource::Correct,
            timestamp: TimestampOffset::Current,
            replay: ReplayState::First,
        },
        Cell {
            label: "stripe_valid_stale_minus_600s",
            provider: Provider::Stripe,
            signature: SignatureSource::Correct,
            timestamp: TimestampOffset::Stale,
            replay: ReplayState::First,
        },
        Cell {
            label: "stripe_valid_future_plus_600s",
            provider: Provider::Stripe,
            signature: SignatureSource::Correct,
            timestamp: TimestampOffset::Future,
            replay: ReplayState::First,
        },
        Cell {
            label: "stripe_valid_replayed",
            provider: Provider::Stripe,
            signature: SignatureSource::Correct,
            timestamp: TimestampOffset::Current,
            replay: ReplayState::Replay,
        },
        Cell {
            label: "stripe_wrong_signature",
            provider: Provider::Stripe,
            signature: SignatureSource::WrongSecret,
            timestamp: TimestampOffset::Current,
            replay: ReplayState::First,
        },
        // Slack: full matrix.
        Cell {
            label: "slack_valid_current",
            provider: Provider::Slack,
            signature: SignatureSource::Correct,
            timestamp: TimestampOffset::Current,
            replay: ReplayState::First,
        },
        Cell {
            label: "slack_valid_stale_minus_600s",
            provider: Provider::Slack,
            signature: SignatureSource::Correct,
            timestamp: TimestampOffset::Stale,
            replay: ReplayState::First,
        },
        Cell {
            label: "slack_valid_replayed",
            provider: Provider::Slack,
            signature: SignatureSource::Correct,
            timestamp: TimestampOffset::Current,
            replay: ReplayState::Replay,
        },
        Cell {
            label: "slack_wrong_signature",
            provider: Provider::Slack,
            signature: SignatureSource::WrongSecret,
            timestamp: TimestampOffset::Current,
            replay: ReplayState::First,
        },
    ];

    // Build receivers + per-provider replay caches.
    let github_receiver = GitHubWebhook::new(GITHUB_SECRET);
    let stripe_receiver = StripeWebhook::new(STRIPE_SECRET);
    let slack_receiver = SlackWebhook::new(SLACK_SECRET);

    let mut rows = Vec::new();
    for cell in &cells {
        // Each cell gets a fresh replay handler so the Replay-vs-First
        // distinction only depends on the cell's own logic, not on
        // bleed from earlier cells.
        let replay_handler = WebhookHandler::new(
            HmacSha256Verifier::new(match cell.provider {
                Provider::GitHub => GITHUB_SECRET,
                Provider::Stripe => STRIPE_SECRET,
                Provider::Slack => SLACK_SECRET,
            }),
            cell.provider.label(),
        );

        let verdict = match cell.provider {
            Provider::GitHub => github_cell(cell, &github_receiver, &replay_handler),
            Provider::Stripe => stripe_cell(cell, &stripe_receiver, &replay_handler),
            Provider::Slack => slack_cell(cell, &slack_receiver, &replay_handler),
        };

        rows.push(format!(
            "{:<48} | provider={} verdict={}",
            cell.label,
            cell.provider.label(),
            verdict.label(),
        ));
    }

    let preamble = "\
# Golden vector — webhook signature verification matrix
# br-87544f4d5 (CrimsonWolf streaming) +
# br-54776a265 (CrimsonWolf webhook delivery retry)
# Format:
#   <cell-label>  | provider=<p> verdict=<v>
# Verdicts:
#   - Accepted: signature OK, timestamp in window, no replay
#   - InvalidSignature: HMAC mismatch (or signature header missing)
#   - TimestampOutOfWindow: signature OK but timestamp ±tolerance
#   - Replay: signature/timestamp OK but event id seen before
# Determinism notes:
#   - HMAC-SHA256 is deterministic from secret + body
#   - Stale (-600s) and Future (+600s) are both well outside the
#     300s default tolerance, so their bucket is stable across runs
#   - GitHub has no timestamp window (uses delivery id only)
#   - Each cell gets a fresh replay cache so isolation holds

";
    let mut out = String::new();
    out.push_str(preamble);
    for row in &rows {
        out.push_str(row);
        out.push('\n');
    }
    out
}

#[test]
fn golden_webhook_signature_matrix_canonical_cells() {
    let actual = render_golden();
    insta::assert_snapshot!("webhook_signature_matrix_canonical_cells", actual);
}
