//! xorpl — obfuscated attestation compiler.
//!
//! # Pipeline
//!
//! ```text
//! Expr  ──lower()──►  Circuit  ──ConcreteVm::from_circuit()──►  ConcreteVm  ──emit()──►  Rust source
//!  │                    │
//! ast.rs             vm.rs (also owns Builder)
//! lower.rs           emit.rs reads ConcreteVm
//! ```
//!
//! The server mirrors only the `Circuit` (value graph) and calls
//! `Circuit::eval()` to verify checksums — it never sees masks or constants.

pub mod ast;
pub mod emit;
pub mod fixture_defs;
pub mod lower;
pub mod vm;
