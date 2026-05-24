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
    /// If `Some`, the base expression is passed through `strong_rotate` with
    /// this seed before lowering.  Use distinct values per rotated fixture to
    /// get distinct circuit shapes.
    pub structure_seed: Option<u64>,
    /// Builds the expression tree for this circuit.
    pub build: fn() -> Rc<Expr>,
}

impl FixtureDef {
    /// Return the expression to lower, applying `strong_rotate` when
    /// `structure_seed` is set.  Both `regen_fixtures` and the skew check call
    /// this so they always agree on what to emit.
    pub fn expr(&self) -> Rc<Expr> {
        let base = (self.build)();
        if let Some(ss) = self.structure_seed {
            use rand::SeedableRng;
            let mut rng = rand::rngs::StdRng::seed_from_u64(ss);
            crate::ast::strong_rotate(&base, &mut rng)
        } else {
            base
        }
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// All registered emit fixtures.
///
/// Add entries here to extend the skew check, structural tests, and the
/// regen binary.  See the module-level doc for the full checklist.
pub static ALL_FIXTURES: &[FixtureDef] = &[
    FixtureDef { name: "or_rotl_demo",      seed: 0, structure_seed: None,     build: build_or_rotl_demo  },
    FixtureDef { name: "add32_demo",         seed: 0, structure_seed: None,     build: build_add32_demo    },
    FixtureDef { name: "mux_demo",           seed: 0, structure_seed: None,     build: build_mux_demo      },
    FixtureDef { name: "chacha_qr",          seed: 0, structure_seed: None,     build: build_chacha_qr     },
    FixtureDef { name: "chacha_qr_rotated",  seed: 0, structure_seed: Some(42), build: build_chacha_qr     },
    FixtureDef { name: "or_rotl_mux_decoy", seed: 0, structure_seed: None,     build: build_or_rotl_mux_decoy },
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

/// F(a,b,c,d) = ChaCha quarter-round folded to one word.
///
/// Implements one ChaCha quarter-round in SSA form and XORs the four
/// output words into a single 32-bit checksum:
///
/// ```text
/// a += b; d ^= a; d <<<= 16;
/// c += d; b ^= c; b <<<= 12;
/// a += b; d ^= a; d <<<= 8;
/// c += d; b ^= c; b <<<= 7;
/// output = a ^ b ^ c ^ d
/// ```
///
/// Exercises all ARX primitives (Add, Xor, Rotl) and four rounds of the
/// carry chain.  The rotated variant (`chacha_qr_rotated`) applies
/// `strong_rotate` on top, producing a structurally different image.
/// F(a, b) = or_rotl_demo(a, b), but wrapped in one explicit MUX decoy.
///
/// Uses `ast::decoy_mux` so the dead branch is constructed the same way
/// `inject_decoys` would; `And(a, b)` is the garbage operand.
fn build_or_rotl_mux_decoy() -> Rc<Expr> {
    let a = Expr::input("a");
    let b = Expr::input("b");
    let base = build_or_rotl_demo();
    crate::ast::decoy_mux(base, Expr::and(a, b))
}

fn build_chacha_qr() -> Rc<Expr> {
    let a = Expr::input("a");
    let b = Expr::input("b");
    let c = Expr::input("c");
    let d = Expr::input("d");

    let a1 = Expr::add(a,         b.clone());
    let d2 = Expr::rotl(Expr::xor(d,         a1.clone()), 16);
    let c1 = Expr::add(c,         d2.clone());
    let b2 = Expr::rotl(Expr::xor(b,         c1.clone()), 12);
    let a2 = Expr::add(a1,        b2.clone());
    let d4 = Expr::rotl(Expr::xor(d2,        a2.clone()),  8);
    let c2 = Expr::add(c1,        d4.clone());
    let b4 = Expr::rotl(Expr::xor(b2,        c2.clone()),  7);

    Expr::xor(Expr::xor(a2, b4), Expr::xor(c2, d4))
}
