//! xorpl — obfuscated attestation compiler.
//!
//! # Pipeline
//!
//! ```text
//! Expr  ──lower()──►  Circuit  ──ConcreteVm::from_circuit()──►  ConcreteVm  ──emit()──►  Rust source
//!  │                    │
//! expr.rs            vm.rs (also owns Builder)
//! expr_transform.rs  emit.rs reads ConcreteVm
//! lower.rs
//! ```
//!
//! The server mirrors only the `Circuit` (value graph) and calls
//! `Circuit::eval()` to verify checksums — it never sees masks or constants.

pub mod expr;
pub mod expr_transform;
pub mod circuit_transform;
pub mod emit;
#[cfg(feature = "fixture-defs")]
pub mod fixture_defs;
pub mod lower;
pub mod vm;
