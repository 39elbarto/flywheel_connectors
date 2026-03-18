//! FCP MySQL/MariaDB Connector
//!
//! Provides SQL query execution, schema introspection, transaction management,
//! and batch operations via a MySQL REST API proxy.

#![forbid(unsafe_code)]
#![allow(dead_code)]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;
