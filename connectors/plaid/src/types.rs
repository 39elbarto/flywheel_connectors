//! Plaid API types.

use serde::{Deserialize, Serialize};

/// A Plaid account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub account_id: String,
    pub balances: AccountBalances,
    pub mask: Option<String>,
    pub name: String,
    pub official_name: Option<String>,
    pub subtype: Option<String>,
    #[serde(rename = "type")]
    pub account_type: Option<String>,
}

/// Account balance details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountBalances {
    pub available: Option<f64>,
    pub current: Option<f64>,
    pub limit: Option<f64>,
    pub iso_currency_code: Option<String>,
    pub unofficial_currency_code: Option<String>,
}

/// A Plaid transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub transaction_id: String,
    pub account_id: String,
    pub amount: f64,
    pub iso_currency_code: Option<String>,
    pub date: String,
    pub name: String,
    pub merchant_name: Option<String>,
    pub pending: bool,
    pub category: Option<Vec<String>>,
    pub category_id: Option<String>,
    pub authorized_date: Option<String>,
}

/// A Plaid investment holding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Holding {
    pub account_id: String,
    pub security_id: String,
    pub quantity: f64,
    pub institution_price: f64,
    pub institution_value: f64,
    pub cost_basis: Option<f64>,
    pub iso_currency_code: Option<String>,
}

/// A Plaid security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Security {
    pub security_id: String,
    pub name: Option<String>,
    pub ticker_symbol: Option<String>,
    #[serde(rename = "type")]
    pub security_type: Option<String>,
    pub close_price: Option<f64>,
    pub iso_currency_code: Option<String>,
    pub isin: Option<String>,
    pub cusip: Option<String>,
}

/// A Plaid liability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Liability {
    pub account_id: Option<String>,
    #[serde(rename = "type")]
    pub liability_type: Option<String>,
}

/// Credit card liability details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditLiability {
    pub account_id: Option<String>,
    pub is_overdue: Option<bool>,
    pub last_payment_amount: Option<f64>,
    pub last_statement_balance: Option<f64>,
    pub minimum_payment_amount: Option<f64>,
    pub next_payment_due_date: Option<String>,
}

/// Student loan liability details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StudentLoanLiability {
    pub account_id: Option<String>,
    pub disbursement_dates: Option<Vec<String>>,
    pub interest_rate_percentage: Option<f64>,
    pub loan_name: Option<String>,
    pub origination_principal_amount: Option<f64>,
    pub outstanding_interest_amount: Option<f64>,
}

/// Liabilities container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiabilitiesResponse {
    pub credit: Option<Vec<serde_json::Value>>,
    pub mortgage: Option<Vec<serde_json::Value>>,
    pub student: Option<Vec<serde_json::Value>>,
}

/// A Plaid item (linked institution).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaidItem {
    pub item_id: String,
    pub institution_id: Option<String>,
    pub available_products: Option<Vec<String>>,
    pub billed_products: Option<Vec<String>>,
    pub consent_expiration_time: Option<String>,
}

/// Link token creation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkTokenResponse {
    pub link_token: String,
    pub expiration: String,
    pub request_id: Option<String>,
}

/// Access token exchange response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub item_id: String,
    pub request_id: Option<String>,
}

/// Auth numbers response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthNumbers {
    pub ach: Option<Vec<serde_json::Value>>,
    pub eft: Option<Vec<serde_json::Value>>,
    pub international: Option<Vec<serde_json::Value>>,
    pub bacs: Option<Vec<serde_json::Value>>,
}

/// Transactions sync response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionsSyncResponse {
    pub added: Vec<Transaction>,
    pub modified: Vec<Transaction>,
    pub removed: Vec<RemovedTransaction>,
    pub next_cursor: String,
    pub has_more: bool,
}

/// A removed transaction reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovedTransaction {
    pub transaction_id: String,
}

/// Plaid API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct PlaidApiError {
    pub error_type: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub display_message: Option<String>,
    pub request_id: Option<String>,
}
