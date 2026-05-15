//! Cryptographic hardware feature detection and dispatch.
//!
//! This crate owns the small, safe substrate that later acceleration beads use
//! for BLAKE3, AEAD, and lattice/NTT dispatch. It deliberately starts with
//! portable function pointers so unsupported or incorrectly detected hardware
//! always falls back to deterministic safe code.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod blake3;
pub mod cpuid;
pub mod dispatch;

pub use blake3::{Blake3DispatchError, Blake3Hasher, Blake3Tier};
pub use cpuid::{HwFeatureSet, detect};
pub use dispatch::{
    AesGcmDispatch, Blake3Dispatch, DispatchTier, FunctionTable, NttDispatch, build_function_table,
    function_table,
};
