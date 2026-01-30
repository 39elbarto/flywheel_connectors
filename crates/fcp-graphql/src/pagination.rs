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
