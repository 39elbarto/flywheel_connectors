//! Stripe API types.

use serde::{Deserialize, Serialize};

/// A Stripe customer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    pub id: String,
    pub object: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub created: Option<i64>,
    pub livemode: Option<bool>,
}

/// A Stripe payment intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentIntent {
    pub id: String,
    pub object: String,
    pub amount: i64,
    pub currency: String,
    pub status: String,
    pub customer: Option<String>,
    pub created: Option<i64>,
}

/// A Stripe refund.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refund {
    pub id: String,
    pub object: String,
    pub amount: i64,
    pub currency: String,
    pub status: String,
    pub payment_intent: Option<String>,
    pub created: Option<i64>,
}

/// A Stripe subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub object: String,
    pub status: String,
    pub customer: Option<String>,
    pub current_period_start: Option<i64>,
    pub current_period_end: Option<i64>,
    pub created: Option<i64>,
}

/// A Stripe invoice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: String,
    pub object: String,
    pub amount_due: Option<i64>,
    pub currency: Option<String>,
    pub status: Option<String>,
    pub customer: Option<String>,
    pub created: Option<i64>,
}

/// A Stripe deleted resource response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedResource {
    pub id: String,
    pub object: String,
    pub deleted: bool,
}

/// A Stripe balance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    pub object: String,
    pub available: Vec<BalanceAmount>,
    pub pending: Vec<BalanceAmount>,
    pub livemode: Option<bool>,
}

/// Amount in a balance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceAmount {
    pub amount: i64,
    pub currency: String,
}

/// Stripe list response.
#[derive(Debug, Clone, Deserialize)]
pub struct ListResponse {
    pub object: String,
    pub data: Vec<serde_json::Value>,
    pub has_more: bool,
    pub url: Option<String>,
}

/// Stripe API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<ApiErrorDetail>,
}

/// Stripe error detail.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetail {
    pub message: Option<String>,
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub code: Option<String>,
}

/// Stripe webhook event envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeWebhookEvent {
    pub id: String,
    pub object: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub created: i64,
    pub livemode: Option<bool>,
    pub data: StripeWebhookEventData,
}

/// Stripe webhook event payload wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeWebhookEventData {
    pub object: serde_json::Value,
}
