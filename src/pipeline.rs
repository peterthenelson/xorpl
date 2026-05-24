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
//! Expr ──strong_rotate──► Expr' ──lower──► Circuit ──inject_remasks──► Circuit'
//!   ──split_secret_consts──► Circuit'' ──from_circuit──► MaskedCircuit
//! ```
//!
//! The server receives [`Compilation::circuit`] (identified by
//! [`Compilation::rotation_tag`]) and verifies checksums via
//! [`Circuit::eval`].  The browser receives [`Compilation::code`] compiled
//! to Wasm, plus a server verifier emitted by [`crate::emit::emit_verifier_rust`].

use std::rc::Rc;

use rand::RngCore;

use crate::circuit::Circuit;
use crate::circuit_transform::{inject_remasks, split_secret_consts};
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
    /// Structural fingerprint of [`Compilation::circuit`].  Stable across
    /// cheap rotations (same circuit, new masks); changes on strong rotation.
    /// The browser bakes this into its Wasm export and sends it with every
    /// event report so the server can select the matching verifier.
    pub rotation_tag: u32,
    /// Emitted Rust source — the deployable client function.
    pub code: String,
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
/// 4. `split_secret_consts` at rate 1-in-3 — probabilistic constant splitting.
/// 5. `MaskedCircuit::from_circuit` — concretization.
/// 6. `emit_rust` — code generation into `Compilation::code`.
///
/// `fn_name` becomes the emitted function's name and must be a valid Rust
/// identifier.  All randomness comes from `rng`; the caller seeds it however
/// they like.
/// Re-concretize an existing circuit with fresh randomness — a cheap rotation.
///
/// The circuit structure (and therefore [`Compilation::rotation_tag`]) is
/// unchanged; only the mask seed advances, so the emitted `POOL` constants
/// differ from the previous rotation.  Use this to rotate the browser's Wasm
/// bundle frequently without redeploying the server verifier.
///
/// Returns the new `MaskedCircuit` and emitted browser source.  The
/// `rotation_tag` to advertise is still `compilation.rotation_tag`.
pub fn rotate_cheap(compilation: &Compilation, fn_name: &str, rng: &mut impl RngCore) -> (MaskedCircuit, String) {
    let masked = MaskedCircuit::from_circuit(&compilation.circuit, rng);
    let code   = emit_rust(&masked, &compilation.circuit, fn_name, rng);
    (masked, code)
}

pub fn compile(expr: Rc<Expr>, fn_name: &str, rng: &mut impl RngCore) -> Compilation {
    let transformed  = strong_rotate(&expr, rng);
    let circuit      = lower_to_circuit(&transformed);
    let circuit      = inject_remasks(&circuit, rng, 4);
    let circuit      = split_secret_consts(&circuit, rng, 3);
    let rotation_tag = circuit.fingerprint();
    let masked       = MaskedCircuit::from_circuit(&circuit, rng);
    let code         = emit_rust(&masked, &circuit, fn_name, rng);
    Compilation { original_expr: expr, circuit, masked, rotation_tag, code }
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
            let c = compile(Rc::clone(&expr), "checksum", &mut rng);

            let vals = c.circuit.eval(&input_map);
            assert_eq!(vals[&c.circuit.egress], expected,
                "circuit eval wrong (pipeline_seed={pipeline_seed})");

            let (_regs, revealed) = c.masked.eval(&c.circuit, &input_map);
            assert_eq!(revealed, expected,
                "masked eval wrong (pipeline_seed={pipeline_seed})");

            assert!(!c.code.is_empty());
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

    #[test]
    fn rotate_cheap_preserves_semantics() {
        let a = Expr::input("a");
        let b = Expr::input("b");
        let c = Expr::secret_const(0x9e37_79b9);
        let expr = Rc::new(Expr::rotl(Expr::xor(Expr::or(a, b), c), 5));

        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let orig = compile(Rc::clone(&expr), "f", &mut rng);

        let mut rng2 = rand::rngs::StdRng::seed_from_u64(99);
        let (masked2, code2) = rotate_cheap(&orig, "f", &mut rng2);

        // Code strings differ — different POOL constants.
        assert_ne!(orig.code, code2);

        // Semantics unchanged.
        let input_map: std::collections::HashMap<String, u32> =
            [("a", 0x1234_5678u32), ("b", 0xDEAD_BEEFu32)]
            .iter().map(|&(k, v)| (k.to_string(), v)).collect();
        let (_regs, result) = masked2.eval(&orig.circuit, &input_map);
        let expected = ((0x1234_5678u32 | 0xDEAD_BEEFu32) ^ 0x9e37_79b9u32).rotate_left(5);
        assert_eq!(result, expected);
    }

    #[test]
    fn rotate_cheap_embeds_same_rotation_tag() {
        let expr = Rc::new(Expr::xor(Expr::input("a"), Expr::input("b")));
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let orig = compile(Rc::clone(&expr), "f", &mut rng);

        let mut rng2 = rand::rngs::StdRng::seed_from_u64(1);
        let (_masked, code) = rotate_cheap(&orig, "f", &mut rng2);

        let tag_hex = format!("0x{:08x}", orig.rotation_tag);
        assert!(code.contains(&tag_hex),
            "cheap rotation must embed the same ROTATION_TAG {tag_hex}");
    }

    #[test]
    fn rotation_tag_stable_across_cheap_rotation() {
        // Cheap rotation = same circuit, new MaskedCircuit seed.
        // Fingerprint depends only on the Circuit, so it must not change.
        let a = Expr::input("a");
        let b = Expr::input("b");
        let c = Expr::secret_const(0x9e37_79b9);
        let expr = Rc::new(Expr::rotl(Expr::xor(Expr::or(a, b), c), 5));

        // Use the same strong-rotate seed so the circuit structure is identical.
        let mut rng1 = rand::rngs::StdRng::seed_from_u64(0);
        let mut rng2 = rand::rngs::StdRng::seed_from_u64(0);

        let c1 = compile(Rc::clone(&expr), "f", &mut rng1);
        let c2 = compile(Rc::clone(&expr), "f", &mut rng2);

        assert_eq!(c1.rotation_tag, c2.rotation_tag,
            "same pipeline seed must yield same rotation_tag");
    }

    #[test]
    fn rotation_tag_differs_across_strong_rotation() {
        let a = Expr::input("a");
        let b = Expr::input("b");
        let c = Expr::secret_const(0x9e37_79b9);
        let expr = Rc::new(Expr::rotl(Expr::xor(Expr::or(a, b), c), 5));

        let mut rng1 = rand::rngs::StdRng::seed_from_u64(1);
        let mut rng2 = rand::rngs::StdRng::seed_from_u64(2);

        let c1 = compile(Rc::clone(&expr), "f", &mut rng1);
        let c2 = compile(Rc::clone(&expr), "f", &mut rng2);

        assert_ne!(c1.rotation_tag, c2.rotation_tag,
            "different pipeline seeds should (almost certainly) yield different rotation_tags");
    }
}
