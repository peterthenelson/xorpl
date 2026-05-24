//! Standard compilation pipeline: `Expr` → deployable Rust source.
//!
//! [`compile`] wires the canonical stage sequence together.  Callers that
//! need to test or demonstrate a specific transform in isolation should call
//! the individual stage functions directly — bypassing this module is
//! intentional and supported.
//!
//! # Stage sequence
//!
//! ```text
//! Expr ──strong_rotate──► Expr' ──lower──► Circuit ──inject_remasks──► Circuit' ──from_circuit──► MaskedCircuit
//! ```
//!
//! The server receives [`Compilation::circuit`] and verifies checksums by
//! calling [`Circuit::eval`] directly.  [`Compilation::emit`] produces the
//! client-side Rust source from [`Compilation::masked`].

use std::rc::Rc;

use rand::RngCore;

use crate::circuit::Circuit;
use crate::circuit_transform::inject_remasks;
use crate::emit::emit_rust;
use crate::expr::Expr;
use crate::expr_transform::strong_rotate;
use crate::lower::lower_to_circuit;
use crate::mask::MaskedCircuit;

// ---------------------------------------------------------------------------
// Compilation artifact
// ---------------------------------------------------------------------------

/// The artifacts produced by one compilation run.
pub struct Compilation {
    /// Pre-transform expression — the canonical definition of F.
    pub original_expr: Rc<Expr>,
    /// Post-transform circuit.  The server mirrors this and calls
    /// [`Circuit::eval`] to verify client checksums.
    pub circuit: Circuit,
    /// Concretized client artifact — baked masks, constants, and triples.
    pub masked: MaskedCircuit,
}

impl Compilation {
    /// Emit the concretized Rust function named `fn_name`.
    ///
    /// `rng` seeds the register-slot shuffle; the caller can use the same RNG
    /// that was passed to `compile` (continuing the sequence) or a fresh one.
    pub fn emit(&self, fn_name: &str, rng: &mut impl RngCore) -> String {
        emit_rust(&self.masked, &self.circuit, fn_name, rng)
    }
}

// ---------------------------------------------------------------------------
// Pipeline entry point
// ---------------------------------------------------------------------------

/// Run the full compilation pipeline on `expr`.
///
/// Stages applied, in order:
/// 1. `strong_rotate` — structural expression-level obfuscation.
/// 2. `lower_to_circuit` — deterministic lowering to a value graph.
/// 3. `inject_remasks` at rate 1-in-4 — post-lowering mask re-randomization.
/// 4. `MaskedCircuit::from_circuit` — concretization.
///
/// All randomness comes from `rng`; the caller seeds it however they like.
/// Holding `rng` state fixed reproduces identical output for the same `expr`.
pub fn compile(expr: Rc<Expr>, rng: &mut impl RngCore) -> Compilation {
    let transformed = strong_rotate(&expr, rng);
    let circuit     = lower_to_circuit(&transformed);
    let circuit     = inject_remasks(&circuit, rng, 4);
    let masked      = MaskedCircuit::from_circuit(&circuit, rng);
    Compilation { original_expr: expr, circuit, masked }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn run(expr: Rc<Expr>, inputs: &[(&str, u32)], expected: u32) {
        let input_map: std::collections::HashMap<String, u32> =
            inputs.iter().map(|&(k, v)| (k.to_string(), v)).collect();

        for pipeline_seed in 0u64..4 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(pipeline_seed);
            let c = compile(Rc::clone(&expr), &mut rng);

            let vals = c.circuit.eval(&input_map);
            assert_eq!(vals[&c.circuit.egress], expected,
                "circuit eval wrong (pipeline_seed={pipeline_seed})");

            let (_regs, revealed) = c.masked.eval(&c.circuit, &input_map);
            assert_eq!(revealed, expected,
                "masked eval wrong (pipeline_seed={pipeline_seed})");

            let src = c.emit("checksum", &mut rng);
            assert!(!src.is_empty());
        }
    }

    #[test]
    fn pipeline_or_rotl() {
        let a = Expr::input("a");
        let b = Expr::input("b");
        let c = Expr::secret_const(0x9e37_79b9);
        let expr = Expr::rotl(Expr::xor(Expr::or(a, b), c), 5);
        let av: u32 = 0x1234_5678;
        let bv: u32 = 0xDEAD_BEEF;
        run(expr, &[("a", av), ("b", bv)], ((av | bv) ^ 0x9e37_79b9u32).rotate_left(5));
    }

    #[test]
    fn pipeline_add32() {
        let expr = Expr::add(Expr::input("a"), Expr::input("b"));
        run(expr, &[("a", 0xFFFF_FFFF), ("b", 1)], 0);
    }

    #[test]
    fn pipeline_chacha_qr() {
        let a = Expr::input("a");
        let b = Expr::input("b");
        let c = Expr::input("c");
        let d = Expr::input("d");
        let a1 = Expr::add(a.clone(),  b.clone());
        let d2 = Expr::rotl(Expr::xor(d.clone(),  a1.clone()), 16);
        let c1 = Expr::add(c.clone(),  d2.clone());
        let b2 = Expr::rotl(Expr::xor(b.clone(),  c1.clone()), 12);
        let a2 = Expr::add(a1,         b2.clone());
        let d4 = Expr::rotl(Expr::xor(d2,         a2.clone()),  8);
        let c2 = Expr::add(c1,         d4.clone());
        let b4 = Expr::rotl(Expr::xor(b2,         c2.clone()),  7);
        let expr = Expr::xor(Expr::xor(a2, b4), Expr::xor(c2, d4));

        let av: u32 = 0x6170_7865;
        let bv: u32 = 0x3320_646e;
        let cv: u32 = 0x7962_2d32;
        let dv: u32 = 0x6b20_6574;
        let circuit = lower_to_circuit(&expr);
        let vals = circuit.eval(
            &[("a", av), ("b", bv), ("c", cv), ("d", dv)]
                .iter().map(|&(k, v)| (k.to_string(), v)).collect()
        );
        let expected = vals[&circuit.egress];

        run(Rc::clone(&expr), &[("a", av), ("b", bv), ("c", cv), ("d", dv)], expected);
    }
}
