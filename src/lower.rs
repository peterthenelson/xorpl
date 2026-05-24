//! Lowering: `Expr` → `Circuit` via `Builder`.
//!
//! This module is the bridge between the expression tree (`ast`) and the
//! gadget-level circuit (`vm`). It never touches `Gadget`, `Wire`, or
//! `ConcreteVm` directly — the `Builder` API is the only interface it uses.
//!
//! # Usage
//!
//! ```ignore
//! let expr = Expr::add(Expr::input("nonce"), Expr::input("event"));
//! let circuit = lower_to_circuit(&expr);
//! let vm = ConcreteVm::from_circuit(&circuit, seed);
//! ```
//!
//! # Memoisation and DAG handling
//!
//! `Rc<Expr>` nodes can be shared (a state word used twice in a ChaCha round
//! appears as the same `Rc`). The lowering pass keeps a
//! `HashMap<*const Expr, WireId>` keyed on `Rc::as_ptr`. When it encounters a
//! node it has already lowered, it returns the cached `WireId` instead of
//! emitting duplicate gadgets. Duplicate output wires would fail
//! `Circuit::validate()`, so this memoisation is required for correctness, not
//! just performance.
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
//!
//! `Ingest` nodes with the same name share one `Gadget::Ingest` (also via the
//! memo map), so writing `Expr::input("a")` twice in an expression does not
//! produce two ingests.

use std::collections::HashMap;
use std::rc::Rc;

use crate::ast::Expr;
use crate::vm::{Builder, Circuit, WireId};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Lower an expression tree to a validated `Circuit`.
///
/// `result` is the wire whose value will be revealed at egress.
/// The returned circuit is ready to pass to `ConcreteVm::from_circuit`.
pub fn lower_to_circuit(expr: &Rc<Expr>) -> Circuit {
    let mut builder  = Builder::new();
    let mut memo: HashMap<*const Expr, WireId> = HashMap::new();
    let result = lower_expr(expr, &mut builder, &mut memo);
    builder.build(result)
}

// ---------------------------------------------------------------------------
// Recursive lowering (stub)
// ---------------------------------------------------------------------------

/// Recursively lower one expression node, using `memo` to avoid re-emitting
/// shared nodes. Returns the `WireId` of the node's output wire.
fn lower_expr(
    expr:    &Rc<Expr>,
    builder: &mut Builder,
    memo:    &mut HashMap<*const Expr, WireId>,
) -> WireId {
    // Check memo before doing any work.
    let ptr = Rc::as_ptr(expr);
    if let Some(&wire) = memo.get(&ptr) {
        return wire;
    }

    let wire = match expr.as_ref() {
        // --- sources ---
        Expr::Input(name)       => builder.ingest(name),
        Expr::PublicConst(k)    => builder.public_const(*k),
        Expr::SecretConst(k)    => builder.secret_const(*k),

        // --- direct gadget mappings ---
        Expr::Xor(a, b) => {
            let wa = lower_expr(a, builder, memo);
            let wb = lower_expr(b, builder, memo);
            builder.xor(wa, wb)
        }
        Expr::And(a, b) => {
            let wa = lower_expr(a, builder, memo);
            let wb = lower_expr(b, builder, memo);
            builder.and(wa, wb)
        }
        Expr::Rotl(a, r) => {
            let wa = lower_expr(a, builder, memo);
            builder.rotl(wa, *r)
        }

        // --- expansions ---
        Expr::Or(a, b) => {
            // a | b  =  (a ^ b) ^ (a & b)
            let wa = lower_expr(a, builder, memo);
            let wb = lower_expr(b, builder, memo);
            let xor_ab = builder.xor(wa, wb);
            let and_ab = builder.and(wa, wb);
            builder.xor(xor_ab, and_ab)
        }
        Expr::Not(a) => {
            // !a  =  a ^ 0xffff_ffff  (free: mask propagates linearly)
            let wa = lower_expr(a, builder, memo);
            builder.xor_const(wa, 0xffff_ffff)
        }
        Expr::Add(a, b) => {
            let wa = lower_expr(a, builder, memo);
            let wb = lower_expr(b, builder, memo);
            builder.add32(wa, wb)
        }
        Expr::Mux { cond, on_true, on_false } => {
            // select(c, t, f)  =  f ^ (c & (t ^ f))  — 1 triple
            let wc = lower_expr(cond, builder, memo);
            let wt = lower_expr(on_true, builder, memo);
            let wf = lower_expr(on_false, builder, memo);
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
    use crate::ast::Expr;
    use crate::vm::ConcreteVm;

    fn str_map(inputs: &[(&str, u32)]) -> std::collections::HashMap<String, u32> {
        inputs.iter().map(|&(k, v)| (k.to_string(), v)).collect()
    }

    // Concretize with several seeds and assert every masked eval reveals `expected`.
    fn verify(expr: &Rc<Expr>, inputs: &[(&str, u32)], expected: u32) {
        let circuit = lower_to_circuit(expr);
        let input_map = str_map(inputs);
        for seed in 0u64..8 {
            let vm = ConcreteVm::from_circuit(&circuit, seed);
            let (_regs, revealed) = vm.eval(&input_map);
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
        // all-ones selects on_true
        verify(&expr, &[("c", 0xFFFF_FFFF), ("t", 0xAAAA_AAAA), ("f", 0x5555_5555)], 0xAAAA_AAAA);
        // all-zeros selects on_false
        verify(&expr, &[("c", 0x0000_0000), ("t", 0xAAAA_AAAA), ("f", 0x5555_5555)], 0x5555_5555);
        // bitwise: alternating bits select alternating halves
        verify(&expr, &[("c", 0xFFFF_0000), ("t", 0xDEAD_BEEF), ("f", 0xCAFE_BABE)], 0xDEAD_BABE);
    }

    #[test]
    fn shared_node_not_duplicated() {
        // `a` appears as both inputs to XOR — memoisation must not emit two ingests.
        let a = Expr::input("a");
        let expr = Expr::xor(a.clone(), a.clone());
        // x ^ x == 0 for any x
        verify(&expr, &[("a", 0x1234_5678)], 0);
        verify(&expr, &[("a", 0xFFFF_FFFF)], 0);
    }

    #[test]
    fn composed_or_not() {
        // De Morgan: !(a | b)  ==  !a & !b
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
        // F(a, b) = rotl((a | b) ^ C, 5)  — the demo circuit, via ast/lower
        let a = Expr::input("a");
        let b = Expr::input("b");
        let c = Expr::secret_const(0x9e37_79b9);
        let or_ab  = Expr::or(a.clone(), b.clone());
        let xor_c  = Expr::xor(or_ab, c);
        let expr   = Expr::rotl(xor_c, 5);

        let av: u32 = 0x1234_5678;
        let bv: u32 = 0xDEAD_BEEF;
        let expected = ((av | bv) ^ 0x9e37_79b9).rotate_left(5);
        verify(&expr, &[("a", av), ("b", bv)], expected);
    }
}
