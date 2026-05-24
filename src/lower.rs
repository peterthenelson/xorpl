//! Lowering: `Expr` → `Circuit` via `Builder`.
//!
//! This module is the bridge between the expression tree (`expr`) and the
//! gadget-level circuit (`circuit`). It never touches `Gadget`, `Wire`, or
//! `MaskedCircuit` directly — the `Builder` API is the only interface it uses.
//!
//! # Usage
//!
//! ```ignore
//! let expr    = Expr::add(Expr::input("nonce"), Expr::input("event"));
//! let circuit = lower_to_circuit(&expr);
//! let masked  = MaskedCircuit::from_circuit(&circuit, &mut rng);
//! ```
//!
//! # Memoisation and DAG handling
//!
//! `Rc<Expr>` nodes can be shared (a state word used twice in a ChaCha round
//! appears as the same `Rc`). The lowering pass keeps two dedup maps:
//!
//! - `memo: HashMap<*const Expr, WireId>` — keyed on `Rc::as_ptr`.  Avoids
//!   re-emitting gadgets for any shared `Rc` node.
//! - `ingest_map: HashMap<String, WireId>` — keyed on input name.  Ensures
//!   that two separately-constructed `Expr::Input("a")` nodes (different `Rc`s,
//!   same name) map to the same `Gadget::Ingest` rather than producing two
//!   ingests with different masks.
//!
//! # Expansions
//!
//! Composite `Expr` variants that have no direct `Gadget` equivalent are
//! expanded here:
//!
//! | `Expr` variant | Expansion |
//! |----------------|-----------|
//! | `Or(a, b)` | `Xor(Xor(a,b), And(a,b))` — standard OR from XOR+AND |
//! | `Not(a)` | `XorConst(a, 0xffff_ffff)` — free, no triple |
//! | `Add(a, b)` | `Builder::add32(a, b)` — 31 triples |
//! | `Mux{c,t,f}` | `Xor(f, And(c, Xor(t, f)))` — 1 triple |

use std::collections::HashMap;
use std::rc::Rc;

use crate::circuit::{Builder, Circuit, WireId};
use crate::expr::Expr;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Lower an expression tree to a validated `Circuit`.
///
/// The returned circuit is ready to pass to `MaskedCircuit::from_circuit`.
pub fn lower_to_circuit(expr: &Rc<Expr>) -> Circuit {
    let mut builder = Builder::new();
    let mut memo: HashMap<*const Expr, WireId> = HashMap::new();
    let mut ingest_map: HashMap<String, WireId> = HashMap::new();
    let result = lower_expr(expr, &mut builder, &mut memo, &mut ingest_map);
    builder.build(result)
}

// ---------------------------------------------------------------------------
// Recursive lowering
// ---------------------------------------------------------------------------

/// Recursively lower one expression node.  Returns the `WireId` of the
/// node's output wire.
///
/// `memo` deduplicates on `Rc` pointer identity.  `ingest_map` additionally
/// deduplicates named inputs by name, so two separately-created
/// `Expr::Input("a")` nodes share one `Gadget::Ingest`.
fn lower_expr(
    expr:       &Rc<Expr>,
    builder:    &mut Builder,
    memo:       &mut HashMap<*const Expr, WireId>,
    ingest_map: &mut HashMap<String, WireId>,
) -> WireId {
    let ptr = Rc::as_ptr(expr);
    if let Some(&wire) = memo.get(&ptr) {
        return wire;
    }

    let wire = match expr.as_ref() {
        // --- sources ---
        Expr::Input(name) => {
            // Deduplicate by name so that separately-constructed Input nodes
            // with the same name share one ingest gadget (and one mask).
            if let Some(&existing) = ingest_map.get(name.as_str()) {
                existing
            } else {
                let w = builder.ingest(name);
                ingest_map.insert(name.clone(), w);
                w
            }
        }
        Expr::PublicConst(k) => builder.public_const(*k),
        Expr::SecretConst(k) => builder.secret_const(*k),

        // --- direct gadget mappings ---
        Expr::Xor(a, b) => {
            let wa = lower_expr(a, builder, memo, ingest_map);
            let wb = lower_expr(b, builder, memo, ingest_map);
            builder.xor(wa, wb)
        }
        Expr::And(a, b) => {
            let wa = lower_expr(a, builder, memo, ingest_map);
            let wb = lower_expr(b, builder, memo, ingest_map);
            builder.and(wa, wb)
        }
        Expr::Rotl(a, r) => {
            let wa = lower_expr(a, builder, memo, ingest_map);
            builder.rotl(wa, *r)
        }

        // --- expansions ---
        Expr::Or(a, b) => {
            // a | b  =  (a ^ b) ^ (a & b)
            let wa = lower_expr(a, builder, memo, ingest_map);
            let wb = lower_expr(b, builder, memo, ingest_map);
            let xor_ab = builder.xor(wa, wb);
            let and_ab = builder.and(wa, wb);
            builder.xor(xor_ab, and_ab)
        }
        Expr::Not(a) => {
            // !a  =  a ^ 0xffff_ffff  (free: mask propagates linearly)
            let wa = lower_expr(a, builder, memo, ingest_map);
            builder.xor_const(wa, 0xffff_ffff)
        }
        Expr::Add(a, b) => {
            let wa = lower_expr(a, builder, memo, ingest_map);
            let wb = lower_expr(b, builder, memo, ingest_map);
            builder.add32(wa, wb)
        }
        Expr::Mux { cond, on_true, on_false } => {
            // select(c, t, f)  =  f ^ (c & (t ^ f))  — 1 triple
            let wc = lower_expr(cond, builder, memo, ingest_map);
            let wt = lower_expr(on_true, builder, memo, ingest_map);
            let wf = lower_expr(on_false, builder, memo, ingest_map);
            let diff   = builder.xor(wt, wf);
            let masked = builder.and(wc, diff);
            builder.xor(wf, masked)
        }
    };

    memo.insert(ptr, wire);
    wire
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::Expr;
    use crate::mask::MaskedCircuit;

    fn str_map(inputs: &[(&str, u32)]) -> std::collections::HashMap<String, u32> {
        inputs.iter().map(|&(k, v)| (k.to_string(), v)).collect()
    }

    // Concretize with several seeds and assert every masked eval reveals `expected`.
    fn verify(expr: &Rc<Expr>, inputs: &[(&str, u32)], expected: u32) {
        use rand::SeedableRng;
        let circuit = lower_to_circuit(expr);
        let input_map = str_map(inputs);
        for seed in 0u64..8 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let vm = MaskedCircuit::from_circuit(&circuit, &mut rng);
            let (_regs, revealed) = vm.eval(&circuit, &input_map);
            assert_eq!(revealed, expected, "seed={seed}");
        }
    }

    #[test]
    fn or_expansion() {
        let a = Expr::input("a");
        let b = Expr::input("b");
        let expr = Expr::or(a, b);
        verify(&expr, &[("a", 0xF0F0_F0F0), ("b", 0x0F0F_0F0F)], 0xFFFF_FFFF);
        verify(&expr, &[("a", 0xAAAA_AAAA), ("b", 0x5555_5555)], 0xFFFF_FFFF);
        verify(&expr, &[("a", 0x1234_5678), ("b", 0x0000_0000)], 0x1234_5678);
    }

    #[test]
    fn not_expansion() {
        let a = Expr::input("a");
        let expr = Expr::not(a);
        verify(&expr, &[("a", 0x0000_0000)], 0xFFFF_FFFF);
        verify(&expr, &[("a", 0xFFFF_FFFF)], 0x0000_0000);
        verify(&expr, &[("a", 0xAAAA_AAAA)], 0x5555_5555);
    }

    #[test]
    fn add_expansion() {
        let a = Expr::input("a");
        let b = Expr::input("b");
        let expr = Expr::add(a, b);
        verify(&expr, &[("a", 1), ("b", 1)], 2);
        verify(&expr, &[("a", 0xFFFF_FFFF), ("b", 1)], 0); // wrapping
        verify(&expr, &[("a", 0x1234_5678), ("b", 0x8765_4321)], 0x1234_5678u32.wrapping_add(0x8765_4321));
    }

    #[test]
    fn mux_expansion() {
        let c = Expr::input("c");
        let t = Expr::input("t");
        let f = Expr::input("f");
        let expr = Expr::mux(c.clone(), t.clone(), f.clone());
        verify(&expr, &[("c", 0xFFFF_FFFF), ("t", 0xAAAA_AAAA), ("f", 0x5555_5555)], 0xAAAA_AAAA);
        verify(&expr, &[("c", 0x0000_0000), ("t", 0xAAAA_AAAA), ("f", 0x5555_5555)], 0x5555_5555);
        verify(&expr, &[("c", 0xFFFF_0000), ("t", 0xDEAD_BEEF), ("f", 0xCAFE_BABE)], 0xDEAD_BABE);
    }

    #[test]
    fn shared_node_not_duplicated() {
        let a = Expr::input("a");
        let expr = Expr::xor(a.clone(), a.clone());
        verify(&expr, &[("a", 0x1234_5678)], 0);
        verify(&expr, &[("a", 0xFFFF_FFFF)], 0);
    }

    #[test]
    fn separate_rc_same_name_shares_ingest() {
        // Two independently-created Expr::Input("a") must map to the same
        // ingest gadget, not produce two separate masked copies.
        let a1 = Expr::input("a");
        let a2 = Expr::input("a"); // different Rc, same name
        assert!(!std::rc::Rc::ptr_eq(&a1, &a2));
        let expr = Expr::xor(a1, a2);
        // x ^ x == 0 for any x (only holds if both sides are the same wire)
        verify(&expr, &[("a", 0x1234_5678)], 0);
        verify(&expr, &[("a", 0xFFFF_FFFF)], 0);
        verify(&expr, &[("a", 0xDEAD_BEEF)], 0);
    }

    #[test]
    fn composed_or_not() {
        let a = Expr::input("a");
        let b = Expr::input("b");
        let lhs = Expr::not(Expr::or(a.clone(), b.clone()));
        let rhs = Expr::and(Expr::not(a), Expr::not(b));
        let inputs = [("a", 0x1234_5678u32), ("b", 0xABCD_EF01u32)];
        let expected = !(0x1234_5678u32 | 0xABCD_EF01u32);
        verify(&lhs, &inputs, expected);
        verify(&rhs, &inputs, expected);
    }

    #[test]
    fn full_pipeline_example() {
        let a = Expr::input("a");
        let b = Expr::input("b");
        let c = Expr::secret_const(0x9e37_79b9);
        let or_ab = Expr::or(a.clone(), b.clone());
        let xor_c = Expr::xor(or_ab, c);
        let expr  = Expr::rotl(xor_c, 5);

        let av: u32 = 0x1234_5678;
        let bv: u32 = 0xDEAD_BEEF;
        let expected = ((av | bv) ^ 0x9e37_79b9).rotate_left(5);
        verify(&expr, &[("a", av), ("b", bv)], expected);
    }
}
