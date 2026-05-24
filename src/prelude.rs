//! Convenience re-exports for downstream crates.
//!
//! ```rust,ignore
//! use xorpl::prelude::*;
//! ```

pub use crate::circuit::Circuit;
pub use crate::emit::{emit_rust, emit_verifier_rust};
pub use crate::expr::Expr;
pub use crate::lower::lower_to_circuit;
pub use crate::mask::MaskedCircuit;
pub use crate::pipeline::{compile, rotate_cheap, Compilation};
