//! Pagination helpers for GraphQL APIs.

use std::future::Future;

use thiserror::Error;

use crate::error::GraphqlClientError;

/// Cursor-based page info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPageInfo {
    /// Whether there is another page.
    pub has_next_page: bool,
    /// Cursor for the next page.
    pub end_cursor: Option<String>,
    /// Optional total count.
    pub total_count: Option<u64>,
}

/// Cursor-based page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPage<T> {
    /// Items in the page.
    pub items: Vec<T>,
    /// Pagination info.
    pub page_info: CursorPageInfo,
}

/// Offset-based page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffsetPage<T> {
    /// Items in the page.
    pub items: Vec<T>,
    /// Offset of the next page.
    pub next_offset: Option<u64>,
    /// Optional total count.
    pub total_count: Option<u64>,
}

/// Page limit configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageLimit {
    /// Maximum number of items to fetch.
    pub max_items: usize,
}

impl PageLimit {
    /// Create a new limit.
    #[must_use]
    pub const fn new(max_items: usize) -> Self {
        Self { max_items }
    }
}

/// Pagination error type.
#[derive(Debug, Error)]
pub enum PaginationError {
    /// Underlying client error.
    #[error("pagination fetch failed: {0}")]
    Client(#[from] GraphqlClientError),

    /// Pagination limit exceeded.
    #[error("pagination limit exceeded: {0}")]
    LimitExceeded(String),
}

/// Paginate a cursor-based API.
pub async fn paginate_cursor<T, F, Fut>(
    mut cursor: Option<String>,
    limit: Option<PageLimit>,
    mut fetch_page: F,
) -> Result<Vec<T>, PaginationError>
where
    F: FnMut(Option<String>) -> Fut,
    Fut: Future<Output = Result<CursorPage<T>, GraphqlClientError>>,
{
    let mut out = Vec::new();
    let max_items = limit.map(|limit| limit.max_items);
    loop {
        if let Some(max_items) = max_items {
            if out.len() >= max_items {
                return Err(PaginationError::LimitExceeded(
                    "page limit reached".to_string(),
                ));
            }
        }

        let page = fetch_page(cursor.clone()).await?;
        let remaining = max_items.map(|max_items| max_items.saturating_sub(out.len()));
        if let Some(remaining) = remaining {
            if remaining == 0 {
                return Err(PaginationError::LimitExceeded(
                    "page limit reached".to_string(),
                ));
            }
            if page.items.len() > remaining {
                out.extend(page.items.into_iter().take(remaining));
                return Err(PaginationError::LimitExceeded(
                    "page limit reached".to_string(),
                ));
            }
        }
        out.extend(page.items);

        if !page.page_info.has_next_page {
            break;
        }
        cursor.clone_from(&page.page_info.end_cursor);
        if cursor.is_none() {
            break;
        }
    }

    Ok(out)
}

/// Paginate an offset-based API.
#[allow(clippy::missing_errors_doc)]
pub async fn paginate_offset<T, F, Fut>(
    mut offset: u64,
    limit: Option<PageLimit>,
    mut fetch_page: F,
) -> Result<Vec<T>, PaginationError>
where
    F: FnMut(u64) -> Fut,
    Fut: Future<Output = Result<OffsetPage<T>, GraphqlClientError>>,
{
    let mut out = Vec::new();
    let max_items = limit.map(|limit| limit.max_items);
    loop {
        if let Some(max_items) = max_items {
            if out.len() >= max_items {
                return Err(PaginationError::LimitExceeded(
                    "page limit reached".to_string(),
                ));
            }
        }

        let page = fetch_page(offset).await?;
        let remaining = max_items.map(|max_items| max_items.saturating_sub(out.len()));
        if let Some(remaining) = remaining {
            if remaining == 0 {
                return Err(PaginationError::LimitExceeded(
                    "page limit reached".to_string(),
                ));
            }
            if page.items.len() > remaining {
                out.extend(page.items.into_iter().take(remaining));
                return Err(PaginationError::LimitExceeded(
                    "page limit reached".to_string(),
                ));
            }
        }
        out.extend(page.items);

        match page.next_offset {
            Some(next) => offset = next,
            None => break,
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PageLimit ----

    #[test]
    fn page_limit_new() {
        let limit = PageLimit::new(100);
        assert_eq!(limit.max_items, 100);
    }

    #[test]
    fn page_limit_eq() {
        assert_eq!(PageLimit::new(10), PageLimit::new(10));
        assert_ne!(PageLimit::new(10), PageLimit::new(20));
    }

    // ---- CursorPageInfo ----

    #[test]
    fn cursor_page_info_clone_eq() {
        let info = CursorPageInfo {
            has_next_page: true,
            end_cursor: Some("abc".into()),
            total_count: Some(42),
        };
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    // ---- CursorPage ----

    #[test]
    fn cursor_page_clone_eq() {
        let page = CursorPage {
            items: vec![1, 2, 3],
            page_info: CursorPageInfo {
                has_next_page: false,
                end_cursor: None,
                total_count: Some(3),
            },
        };
        let cloned = page.clone();
        assert_eq!(page, cloned);
    }

    // ---- OffsetPage ----

    #[test]
    fn offset_page_clone_eq() {
        let page = OffsetPage {
            items: vec!["a", "b"],
            next_offset: Some(10),
            total_count: None,
        };
        let cloned = page.clone();
        assert_eq!(page, cloned);
    }

    // ---- PaginationError ----

    #[test]
    fn pagination_error_display_limit() {
        let err = PaginationError::LimitExceeded("too many".into());
        assert!(err.to_string().contains("too many"));
    }

    #[test]
    fn pagination_error_from_client_error() {
        let client_err = GraphqlClientError::Json("bad".into());
        let err: PaginationError = client_err.into();
        assert!(err.to_string().contains("pagination fetch"));
    }
}
