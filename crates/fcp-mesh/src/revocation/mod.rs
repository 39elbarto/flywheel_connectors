//! Revocation freshness helpers.

pub mod hier_vv;

pub use hier_vv::{
    HierarchicalVersionVector, RevocationFreshnessAction, RevocationFreshnessDecision,
    RevocationFreshnessFrontier, VersionVectorOrder,
};
