//! Golden vectors for FCP2 conformance testing.
//!
//! This module provides byte-exact test cases for protocol structures.
//! These vectors are normative: implementations must produce these exact bytes.

pub mod capability;
pub mod core;
pub mod datagram;
pub mod fcpc;
pub mod fcps;
pub mod holder_proof;
pub mod hpke;
pub mod session;
pub mod session_messages;
pub mod replay;
pub mod signing;
