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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn customer_serde() {
        let cust = Customer {
            id: "cus_123".to_string(),
            object: "customer".to_string(),
            email: Some("alice@example.com".to_string()),
            name: Some("Alice".to_string()),
            created: Some(1_700_000_000),
            livemode: Some(false),
        };
        let json = serde_json::to_string(&cust).unwrap();
        let back: Customer = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "cus_123");
    }

    #[test]
    fn payment_intent_serde() {
        let pi = PaymentIntent {
            id: "pi_123".to_string(),
            object: "payment_intent".to_string(),
            amount: 2000,
            currency: "usd".to_string(),
            status: "succeeded".to_string(),
            customer: Some("cus_123".to_string()),
            created: Some(1_700_000_000),
        };
        let json = serde_json::to_string(&pi).unwrap();
        let back: PaymentIntent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.amount, 2000);
        assert_eq!(back.status, "succeeded");
    }

    #[test]
    fn refund_serde() {
        let refund = Refund {
            id: "re_123".to_string(),
            object: "refund".to_string(),
            amount: 500,
            currency: "usd".to_string(),
            status: "succeeded".to_string(),
            payment_intent: Some("pi_123".to_string()),
            created: None,
        };
        let json = serde_json::to_string(&refund).unwrap();
        let back: Refund = serde_json::from_str(&json).unwrap();
        assert_eq!(back.amount, 500);
    }

    #[test]
    fn subscription_serde() {
        let sub = Subscription {
            id: "sub_123".to_string(),
            object: "subscription".to_string(),
            status: "active".to_string(),
            customer: Some("cus_123".to_string()),
            current_period_start: Some(1_700_000_000),
            current_period_end: Some(1_702_592_000),
            created: None,
        };
        let json = serde_json::to_string(&sub).unwrap();
        let back: Subscription = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, "active");
    }

    #[test]
    fn invoice_serde() {
        let inv = Invoice {
            id: "in_123".to_string(),
            object: "invoice".to_string(),
            amount_due: Some(5000),
            currency: Some("usd".to_string()),
            status: Some("paid".to_string()),
            customer: Some("cus_123".to_string()),
            created: None,
        };
        let json = serde_json::to_string(&inv).unwrap();
        let back: Invoice = serde_json::from_str(&json).unwrap();
        assert_eq!(back.amount_due, Some(5000));
    }

    #[test]
    fn deleted_resource_serde() {
        let del = DeletedResource {
            id: "cus_123".to_string(),
            object: "customer".to_string(),
            deleted: true,
        };
        let json = serde_json::to_string(&del).unwrap();
        let back: DeletedResource = serde_json::from_str(&json).unwrap();
        assert!(back.deleted);
    }

    #[test]
    fn balance_serde() {
        let bal = Balance {
            object: "balance".to_string(),
            available: vec![BalanceAmount {
                amount: 10000,
                currency: "usd".to_string(),
            }],
            pending: vec![],
            livemode: Some(false),
        };
        let json = serde_json::to_string(&bal).unwrap();
        let back: Balance = serde_json::from_str(&json).unwrap();
        assert_eq!(back.available.len(), 1);
        assert_eq!(back.available[0].amount, 10000);
    }

    #[test]
    fn list_response_serde() {
        let json = json!({"object": "list", "data": [{"id": "cus_1"}], "has_more": true, "url": "/v1/customers"});
        let resp: ListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.has_more);
        assert_eq!(resp.data.len(), 1);
    }

    #[test]
    fn api_error_response_serde() {
        let json = json!({"error": {"message": "No such customer", "type": "invalid_request_error", "code": "resource_missing"}});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let detail = err.error.unwrap();
        assert_eq!(detail.code.as_deref(), Some("resource_missing"));
    }

    #[test]
    fn webhook_event_serde() {
        let event = StripeWebhookEvent {
            id: "evt_123".to_string(),
            object: "event".to_string(),
            event_type: "customer.created".to_string(),
            created: 1_700_000_000,
            livemode: Some(false),
            data: StripeWebhookEventData {
                object: json!({"id": "cus_123"}),
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"customer.created\""));
        let back: StripeWebhookEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_type, "customer.created");
    }
}
