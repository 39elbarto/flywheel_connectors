//! Internal RaptorQ codec implementation (GF(256) arithmetic, linear algebra,
//! systematic index table, and RFC 6330 codec routines).

pub mod decoder;
pub mod gf256;
pub mod linalg;
pub mod rfc6330;
pub mod systematic;
