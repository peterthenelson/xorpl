//! Standard compilation pipeline: `Expr` → deployable Rust source.
//!
//! [`compile`] wires the canonical obfuscation stage sequence together.
//! [`compile_verifier`] produces the corresponding plaintext server artifact
//! from the same original expression.  Both embed the same [`EXPR_DIGEST`]
//! constant so the server can match browser artifacts to the right verifier.
//!
//! # Stage sequence
//!
//! ```text
//! Original Expr ──expr_digest──► [u8; 32]  (stable tag — never changes)
//!       │
//!       ├─► lower_to_circuit ──► Circuit ──► emit_verifier_rust  (server)
//!       │         (canonical, no transforms)
//!       │
//!       └─► strong_rotate ──► Expr' ──lower──► Circuit'
//!             ──inject_remasks──► ──split_secret_consts──►
//!             ──from_circuit──► MaskedCircuit ──► emit_rust       (browser)
//! ```
//!
//! The `EXPR_DIGEST` embedded in both artifacts comes from the original
//! expression *before* any transforms.  This means cheap rotation, strong
//! rotation, and any future obfuscation variant all produce the same digest,
//! so the server verifier never needs to be redeployed for a rotation.

use std::rc::Rc;

use rand::RngCore;

use crate::circuit::Circuit;
use crate::circuit_transform::{inject_remasks, split_secret_consts};
use crate::emit::{emit_rust, emit_verifier_rust};
use crate::expr::{expr_digest, Expr};
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
    /// Stable digest of [`Compilation::original_expr`].  Identical for every
    /// rotation (cheap or strong) of the same expression.  Embedded in both
    /// the browser artifact and the server verifier so the server can match
    /// incoming reports to the right verifier without redeployment.
    pub expr_digest: [u8; 32],
    /// Emitted Rust source — the deployable client function.
    pub code: String,
}

// ---------------------------------------------------------------------------
// Pipeline entry points
// ---------------------------------------------------------------------------

/// Run the full obfuscation pipeline on `expr`.
///
/// Stages applied, in order:
/// 1. `expr_digest` — stable tag from the original expression (before any
///    transforms); embedded in the emitted output as `EXPR_DIGEST`.
/// 2. `strong_rotate` — structural expression-level obfuscation.
/// 3. `lower_to_circuit` — deterministic lowering to a value graph.
/// 4. `inject_remasks` at rate 1-in-4 — post-lowering mask re-randomization.
/// 5. `split_secret_consts` at rate 1-in-3 — probabilistic constant splitting.
/// 6. `MaskedCircuit::from_circuit` — concretization.
/// 7. `emit_rust` — code generation into `Compilation::code`.
///
/// `fn_name` becomes the emitted function's name and must be a valid Rust
/// identifier.  All randomness comes from `rng`; the caller seeds it however
/// they like.
///
/// `key` is an optional HMAC key: `None` produces a plain SHA-256 digest of
/// the expression; `Some(k)` produces HMAC-SHA-256(k, expr), which prevents
/// observers from verifying guesses about the original expression from the
/// embedded digest.  Use the same key for `compile` and `compile_verifier` so
/// the digests match.
pub fn compile(expr: Rc<Expr>, fn_name: &str, rng: &mut impl RngCore, key: Option<&[u8]>) -> Compilation {
    let digest      = expr_digest(&expr, key);
    let transformed = strong_rotate(&expr, rng);
    let circuit     = lower_to_circuit(&transformed);
    let circuit     = inject_remasks(&circuit, rng, 4);
    let circuit     = split_secret_consts(&circuit, rng, 3);
    let masked      = MaskedCircuit::from_circuit(&circuit, rng);
    let code        = emit_rust(&masked, &circuit, fn_name, rng, &digest);
    Compilation { original_expr: expr, circuit, masked, expr_digest: digest, code }
}

/// Emit the plaintext server verifier for `expr`.
///
/// Lowers the original expression directly (no obfuscation transforms) and
/// emits an unmasked evaluation function.  The embedded `EXPR_DIGEST` matches
/// that produced by [`compile`] for the same `expr` and `key`.
pub fn compile_verifier(expr: &Rc<Expr>, fn_name: &str, key: Option<&[u8]>) -> String {
    let digest  = expr_digest(expr, key);
    let circuit = lower_to_circuit(expr);
    emit_verifier_rust(&circuit, fn_name, &digest)
}

/// Re-concretize an existing circuit with fresh randomness — a cheap rotation.
///
/// The circuit structure and [`Compilation::expr_digest`] are unchanged; only
/// the mask seed advances, so the emitted `POOL` constants differ.  Use this
/// to rotate the browser's Wasm bundle frequently without redeploying the
/// server verifier.
///
/// Returns the new `MaskedCircuit` and emitted browser source.
pub fn rotate_cheap(compilation: &Compilation, fn_name: &str, rng: &mut impl RngCore) -> (MaskedCircuit, String) {
    let masked = MaskedCircuit::from_circuit(&compilation.circuit, rng);
    let code   = emit_rust(&masked, &compilation.circuit, fn_name, rng, &compilation.expr_digest);
    (masked, code)
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
            let c = compile(Rc::clone(&expr), "checksum", &mut rng, None);

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
        let orig = compile(Rc::clone(&expr), "f", &mut rng, None);

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
    fn rotate_cheap_embeds_same_expr_digest() {
        let expr = Rc::new(Expr::xor(Expr::input("a"), Expr::input("b")));
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let orig = compile(Rc::clone(&expr), "f", &mut rng, None);

        let mut rng2 = rand::rngs::StdRng::seed_from_u64(1);
        let (_masked, code2) = rotate_cheap(&orig, "f", &mut rng2);

        // Both emitted sources must contain the same EXPR_DIGEST constant.
        let digest_line = |s: &str| s.lines()
            .skip_while(|l| !l.contains("EXPR_DIGEST"))
            .take_while(|l| !l.contains("];"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(digest_line(&orig.code), digest_line(&code2),
            "cheap rotation must embed the same EXPR_DIGEST");
    }

    #[test]
    fn expr_digest_stable_for_same_expr() {
        // The digest is derived from the original expression before any
        // obfuscation transforms, so it must be identical regardless of the
        // RNG seed used for strong_rotate or masking.
        let a = Expr::input("a");
        let b = Expr::input("b");
        let c = Expr::secret_const(0x9e37_79b9);
        let expr = Rc::new(Expr::rotl(Expr::xor(Expr::or(a, b), c), 5));

        let mut rng1 = rand::rngs::StdRng::seed_from_u64(1);
        let mut rng2 = rand::rngs::StdRng::seed_from_u64(2);

        let c1 = compile(Rc::clone(&expr), "f", &mut rng1, None);
        let c2 = compile(Rc::clone(&expr), "f", &mut rng2, None);

        assert_eq!(c1.expr_digest, c2.expr_digest,
            "same expr must always yield the same digest regardless of rng seed");
    }

    #[test]
    fn expr_digest_differs_for_different_exprs() {
        let expr1 = Expr::xor(Expr::input("a"), Expr::input("b"));
        let expr2 = Expr::and(Expr::input("a"), Expr::input("b"));

        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let c1 = compile(expr1, "f", &mut rng, None);
        let c2 = compile(expr2, "f", &mut rng, None);

        assert_ne!(c1.expr_digest, c2.expr_digest);
    }

    #[test]
    fn expr_digest_differs_with_different_keys() {
        let expr = Rc::new(Expr::xor(Expr::input("a"), Expr::input("b")));

        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let c1 = compile(Rc::clone(&expr), "f", &mut rng, None);
        let c2 = compile(Rc::clone(&expr), "f", &mut rng, Some(b"secret"));

        assert_ne!(c1.expr_digest, c2.expr_digest,
            "keyed digest must differ from unkeyed digest");
    }

    #[test]
    fn compile_verifier_matches_compile_digest() {
        let a = Expr::input("a");
        let b = Expr::input("b");
        let c = Expr::secret_const(0x9e37_79b9);
        let expr = Rc::new(Expr::rotl(Expr::xor(Expr::or(a, b), c), 5));

        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let compilation = compile(Rc::clone(&expr), "f", &mut rng, None);
        let verifier    = compile_verifier(&expr, "f_verify", None);

        // Both artifacts embed the same EXPR_DIGEST.
        let digest_line = |s: &str| s.lines()
            .skip_while(|l| !l.contains("EXPR_DIGEST"))
            .take_while(|l| !l.contains("];"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(digest_line(&compilation.code), digest_line(&verifier),
            "browser artifact and verifier must embed the same EXPR_DIGEST");
    }
}
