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
//! | `Mux{c,t,f}` | `Xor(f, And(Not(c), Xor(t, f)))` — 1 triple |
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
        Expr::Or(_a, _b) => {
            // a | b  =  (a ^ b) ^ (a & b)
            todo!()
        }
        Expr::Not(_a) => {
            // !a  =  a ^ 0xffff_ffff
            todo!()
        }
        Expr::Add(_a, _b) => {
            // a + b  =  Builder::add32 (31 triples, word-level generate opt.)
            todo!()
        }
        Expr::Mux { cond: _cond, on_true: _on_true, on_false: _on_false } => {
            // select(c, t, f)  =  f ^ (c & (t ^ f))
            // Note: Not(cond) expands to XorConst(cond, 0xffff_ffff) which is
            // free, but the AND still consumes one triple.
            todo!()
        }
    };

    memo.insert(ptr, wire);
    wire
}
