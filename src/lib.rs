//! xorpl — obfuscated attestation compiler.
//!
//! # Pipeline
//!
//! ```text
//! Expr ──expr_transform──► Expr' ──lower──► Circuit ──circuit_transform──► Circuit' ──from_circuit──► MaskedCircuit ──emit──► Rust
//! ```
//!
//! [`pipeline::compile`] wires the standard stages together.  Each module can
//! also be called directly for testing or partial pipelines.
//!
//! The server mirrors [`Circuit`] and calls [`Circuit::eval`] to verify
//! checksums — it never sees masks or constants.

pub mod circuit;
pub mod circuit_transform;
pub mod emit;
#[cfg(feature = "fixture-defs")]
pub mod fixture_defs;
pub mod lower;
pub mod mask;
pub mod pipeline;
pub mod prelude;
pub mod expr;
pub mod expr_transform;
