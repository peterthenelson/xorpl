//! Emit fixture registry — test infrastructure, not part of the public API.
//!
//! # How to add a new fixture
//!
//! 1. Write a `build_*()` function below that returns an `Rc<Expr>`.
//! 2. Add a `FixtureDef` entry to `ALL_FIXTURES`.
//! 3. Run `cargo run --bin regen_fixtures` to generate `tests/fixtures/<name>.rs`.
//! 4. In `tests/emit_tests.rs`, add a correctness test block for the new fixture
//!    (copy an existing block and update the name, inputs, and expected value).
//! 5. Commit this file, the new fixture file, and the updated test file together.
//!
//! The skew check (`fixtures_not_out_of_sync`) and structural tests in
//! `tests/emit_tests.rs`, as well as `src/bin/regen_fixtures.rs`, both iterate
//! over `ALL_FIXTURES` and pick up new entries automatically — no changes needed
//! there unless you also want per-fixture correctness assertions.

use std::rc::Rc;

use crate::ast::Expr;

// ---------------------------------------------------------------------------
// Fixture descriptor
// ---------------------------------------------------------------------------

pub struct FixtureDef {
    /// File stem and emitted function name — must be a valid Rust identifier.
    /// Fixture source lives at `tests/fixtures/<name>.rs`.
    pub name: &'static str,
    /// Fixed PRNG seed for concretization.  Changing the seed rotates constants
    /// without changing the circuit shape (a "cheap rotation").
    pub seed: u64,
    /// Builds the expression tree for this circuit.
    pub build: fn() -> Rc<Expr>,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// All registered emit fixtures.
///
/// Add entries here to extend the skew check, structural tests, and the
/// regen binary.  See the module-level doc for the full checklist.
pub static ALL_FIXTURES: &[FixtureDef] = &[
    FixtureDef { name: "or_rotl_demo", seed: 0, build: build_or_rotl_demo },
    FixtureDef { name: "add32_demo",   seed: 0, build: build_add32_demo   },
    FixtureDef { name: "mux_demo",     seed: 0, build: build_mux_demo     },
    // Add new fixtures here ↑
];

// ---------------------------------------------------------------------------
// Circuit builders
// ---------------------------------------------------------------------------

/// F(a, b) = rotl((a | b) ^ C, 5)  where C = 0x9e37_79b9 (secret constant).
///
/// Exercises ingest masking, the OR expansion (one AND triple), secret-const
/// obscuring, and rotation.  Matches the circuit used in `src/bin/demo.rs`.
fn build_or_rotl_demo() -> Rc<Expr> {
    let a = Expr::input("a");
    let b = Expr::input("b");
    let c = Expr::secret_const(0x9e37_79b9);
    Expr::rotl(Expr::xor(Expr::or(a, b), c), 5)
}

/// F(a, b) = a.wrapping_add(b).
///
/// Exercises the 31-triple carry chain produced by Builder::add32.
fn build_add32_demo() -> Rc<Expr> {
    Expr::add(Expr::input("a"), Expr::input("b"))
}

/// F(cond, t, f) = mux(cond, t, f) — bitwise select.
///
/// All-ones cond selects t; all-zeros selects f; mixed cond does bitwise
/// selection.  Exercises the Mux expansion (1 triple).
fn build_mux_demo() -> Rc<Expr> {
    Expr::mux(Expr::input("cond"), Expr::input("t"), Expr::input("f"))
}
