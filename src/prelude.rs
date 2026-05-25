//! Convenience re-exports for downstream crates.
//!
//! ```rust,ignore
//! use xorpl::prelude::*;
//! ```

pub use crate::circuit::Circuit;
pub use crate::emit::{emit_rust, emit_verifier_rust};
pub use crate::expr::{expr_digest, Expr};
pub use crate::lower::lower_to_circuit;
pub use crate::mask::MaskedCircuit;
pub use crate::pipeline::{compile, compile_verifier, rotate_cheap, Compilation};
