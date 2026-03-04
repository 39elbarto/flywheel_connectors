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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- Account ----

    #[test]
    fn account_serde_roundtrip() {
        let json = json!({
            "account_id": "acc_123",
            "balances": {
                "available": 100.50,
                "current": 200.75,
                "limit": null,
                "iso_currency_code": "USD",
                "unofficial_currency_code": null
            },
            "mask": "1234",
            "name": "Checking",
            "official_name": "Premier Checking",
            "subtype": "checking",
            "type": "depository"
        });
        let account: Account = serde_json::from_value(json).unwrap();
        assert_eq!(account.account_id, "acc_123");
        assert_eq!(account.balances.available, Some(100.50));
        assert_eq!(account.account_type, Some("depository".into()));

        let serialized = serde_json::to_value(&account).unwrap();
        assert_eq!(serialized["type"], "depository");
    }

    #[test]
    fn account_optional_fields_null() {
        let json = json!({
            "account_id": "acc_456",
            "balances": {
                "available": null,
                "current": null,
                "limit": null,
                "iso_currency_code": null,
                "unofficial_currency_code": null
            },
            "mask": null,
            "name": "Savings",
            "official_name": null,
            "subtype": null,
            "type": null
        });
        let account: Account = serde_json::from_value(json).unwrap();
        assert!(account.balances.available.is_none());
        assert!(account.mask.is_none());
        assert!(account.account_type.is_none());
    }

    // ---- Transaction ----

    #[test]
    fn transaction_serde_roundtrip() {
        let json = json!({
            "transaction_id": "txn_001",
            "account_id": "acc_123",
            "amount": -42.50,
            "iso_currency_code": "USD",
            "date": "2026-03-01",
            "name": "Coffee Shop",
            "merchant_name": "Blue Bottle",
            "pending": false,
            "category": ["Food and Drink", "Coffee"],
            "category_id": "13005",
            "authorized_date": "2026-02-28"
        });
        let txn: Transaction = serde_json::from_value(json).unwrap();
        assert_eq!(txn.transaction_id, "txn_001");
        assert_eq!(txn.amount, -42.50);
        assert!(!txn.pending);
        assert_eq!(txn.category.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn transaction_minimal_fields() {
        let json = json!({
            "transaction_id": "txn_002",
            "account_id": "acc_456",
            "amount": 10.0,
            "date": "2026-03-02",
            "name": "Transfer",
            "pending": true,
            "iso_currency_code": null,
            "merchant_name": null,
            "category": null,
            "category_id": null,
            "authorized_date": null
        });
        let txn: Transaction = serde_json::from_value(json).unwrap();
        assert!(txn.pending);
        assert!(txn.merchant_name.is_none());
        assert!(txn.category.is_none());
    }

    // ---- Holding ----

    #[test]
    fn holding_serde_roundtrip() {
        let json = json!({
            "account_id": "acc_inv",
            "security_id": "sec_001",
            "quantity": 10.0,
            "institution_price": 150.25,
            "institution_value": 1502.50,
            "cost_basis": 1400.00,
            "iso_currency_code": "USD"
        });
        let holding: Holding = serde_json::from_value(json).unwrap();
        assert_eq!(holding.quantity, 10.0);
        assert_eq!(holding.cost_basis, Some(1400.00));
    }

    // ---- Security ----

    #[test]
    fn security_type_field_renamed() {
        let json = json!({
            "security_id": "sec_001",
            "name": "Apple Inc.",
            "ticker_symbol": "AAPL",
            "type": "equity",
            "close_price": 175.50,
            "iso_currency_code": "USD",
            "isin": "US0378331005",
            "cusip": "037833100"
        });
        let sec: Security = serde_json::from_value(json).unwrap();
        assert_eq!(sec.security_type, Some("equity".into()));
        assert_eq!(sec.ticker_symbol, Some("AAPL".into()));

        let serialized = serde_json::to_value(&sec).unwrap();
        assert_eq!(serialized["type"], "equity");
    }

    // ---- Liability ----

    #[test]
    fn liability_type_field_renamed() {
        let json = json!({
            "account_id": "acc_loan",
            "type": "credit"
        });
        let liab: Liability = serde_json::from_value(json).unwrap();
        assert_eq!(liab.liability_type, Some("credit".into()));
    }

    // ---- CreditLiability ----

    #[test]
    fn credit_liability_optional_fields() {
        let json = json!({
            "account_id": "acc_cc",
            "is_overdue": true,
            "last_payment_amount": 500.00,
            "last_statement_balance": 1200.00,
            "minimum_payment_amount": 25.00,
            "next_payment_due_date": "2026-04-01"
        });
        let cl: CreditLiability = serde_json::from_value(json).unwrap();
        assert_eq!(cl.is_overdue, Some(true));
        assert_eq!(cl.minimum_payment_amount, Some(25.00));
    }

    // ---- StudentLoanLiability ----

    #[test]
    fn student_loan_serde() {
        let json = json!({
            "account_id": "acc_loan",
            "disbursement_dates": ["2020-09-01", "2021-01-15"],
            "interest_rate_percentage": 4.5,
            "loan_name": "Federal Subsidized",
            "origination_principal_amount": 25000.0,
            "outstanding_interest_amount": 500.0
        });
        let sl: StudentLoanLiability = serde_json::from_value(json).unwrap();
        assert_eq!(sl.disbursement_dates.as_ref().unwrap().len(), 2);
        assert_eq!(sl.interest_rate_percentage, Some(4.5));
    }

    // ---- LiabilitiesResponse ----

    #[test]
    fn liabilities_response_empty() {
        let json = json!({
            "credit": null,
            "mortgage": null,
            "student": null
        });
        let resp: LiabilitiesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.credit.is_none());
        assert!(resp.mortgage.is_none());
        assert!(resp.student.is_none());
    }

    // ---- PlaidItem ----

    #[test]
    fn plaid_item_serde() {
        let json = json!({
            "item_id": "item_001",
            "institution_id": "ins_1",
            "available_products": ["transactions", "auth"],
            "billed_products": ["transactions"],
            "consent_expiration_time": "2027-01-01T00:00:00Z"
        });
        let item: PlaidItem = serde_json::from_value(json).unwrap();
        assert_eq!(item.item_id, "item_001");
        assert_eq!(item.available_products.as_ref().unwrap().len(), 2);
    }

    // ---- LinkTokenResponse ----

    #[test]
    fn link_token_response_serde() {
        let json = json!({
            "link_token": "link-sandbox-abc",
            "expiration": "2026-03-02T00:00:00Z",
            "request_id": "req_001"
        });
        let resp: LinkTokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.link_token, "link-sandbox-abc");
    }

    // ---- AccessTokenResponse ----

    #[test]
    fn access_token_response_serde() {
        let json = json!({
            "access_token": "access-sandbox-xyz",
            "item_id": "item_001",
            "request_id": "req_002"
        });
        let resp: AccessTokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.access_token, "access-sandbox-xyz");
    }

    // ---- TransactionsSyncResponse ----

    #[test]
    fn transactions_sync_response_serde() {
        let json = json!({
            "added": [{
                "transaction_id": "txn_new",
                "account_id": "acc_1",
                "amount": 15.0,
                "date": "2026-03-01",
                "name": "Grocery",
                "pending": false,
                "iso_currency_code": "USD",
                "merchant_name": null,
                "category": null,
                "category_id": null,
                "authorized_date": null
            }],
            "modified": [],
            "removed": [{"transaction_id": "txn_old"}],
            "next_cursor": "cursor_abc",
            "has_more": false
        });
        let resp: TransactionsSyncResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.added.len(), 1);
        assert!(resp.modified.is_empty());
        assert_eq!(resp.removed.len(), 1);
        assert_eq!(resp.removed[0].transaction_id, "txn_old");
        assert!(!resp.has_more);
    }

    // ---- PlaidApiError ----

    #[test]
    fn plaid_api_error_serde() {
        let json = json!({
            "error_type": "INVALID_INPUT",
            "error_code": "INVALID_ACCESS_TOKEN",
            "error_message": "The access token is invalid",
            "display_message": "Please reconnect your account",
            "request_id": "req_err"
        });
        let err: PlaidApiError = serde_json::from_value(json).unwrap();
        assert_eq!(err.error_type, Some("INVALID_INPUT".into()));
        assert_eq!(err.error_code, Some("INVALID_ACCESS_TOKEN".into()));
    }

    #[test]
    fn plaid_api_error_all_null() {
        let json = json!({});
        let err: PlaidApiError = serde_json::from_value(json).unwrap();
        assert!(err.error_type.is_none());
        assert!(err.error_message.is_none());
        assert!(err.request_id.is_none());
    }

    // ---- AuthNumbers ----

    #[test]
    fn auth_numbers_serde() {
        let json = json!({
            "ach": [{"account": "acc_1"}],
            "eft": null,
            "international": null,
            "bacs": null
        });
        let auth: AuthNumbers = serde_json::from_value(json).unwrap();
        assert_eq!(auth.ach.as_ref().unwrap().len(), 1);
        assert!(auth.eft.is_none());
    }
}
