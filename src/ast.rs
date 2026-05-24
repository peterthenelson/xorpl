//! Expression tree (AST) for the mixing function F.
//!
//! This layer sits above the circuit. It lets callers write F in terms of
//! familiar arithmetic and bitwise operations; the `lower` module then
//! compiles it down to gadgets via `Builder`.
//!
//! # Sharing and DAG structure
//!
//! Child nodes are stored as `Rc<Expr>` rather than `Box<Expr>`. This lets a
//! single sub-expression appear in multiple positions without cloning it.
//! The lowering pass uses pointer identity (`Rc::as_ptr`) as a memoisation
//! key, so each shared node is emitted as exactly one gadget. With `Box`
//! instead, a shared sub-tree would produce duplicate output wires that
//! `Circuit::validate()` would correctly reject.
//!
//! # Supported operations
//!
//! | Variant | Notes |
//! |---------|-------|
//! | `Input` | Named runtime input; becomes `Gadget::Ingest` |
//! | `PublicConst` | Compile-time constant the server also knows; mask = 0 |
//! | `SecretConst` | Compile-time constant hidden by a fresh mask |
//! | `Xor` | Free (mask propagates linearly) |
//! | `And` | Metered — consumes one Beaver triple |
//! | `Or` | Expanded to `Xor(Xor(a,b), And(a,b))` during lowering |
//! | `Not` | Expanded to `XorConst(a, 0xffff_ffff)` |
//! | `Add` | Expanded to `Builder::add32` (31 triples, word-level opt.) |
//! | `Rotl` | Free |
//! | `Mux` | Expanded to `Xor(f, And(c, Xor(t, f)))` |
//!
//! # Transformations
//!
//! Transformations operate on `Rc<Expr>` trees and return a new `Rc<Expr>`.
//! They are the mechanism for "strong rotation": two concretizations with the
//! same seed but different transformed ASTs produce images with different
//! shapes, not just different constants.
//!
//! Planned transforms (all stubs for now):
//! - `constant_fold`   — evaluate constant sub-expressions at compile time
//! - `reassociate`     — reorder XOR/AND trees to change gadget topology
//! - `inject_decoys`   — splice in sub-expressions that evaluate to a constant
//!                       and are dropped at egress; pads the circuit shape
//! - `apply_identity`  — randomly apply algebraic identities
//!                       (double-NOT, De Morgan, etc.)

use std::rc::Rc;

// ---------------------------------------------------------------------------
// Expression tree
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Expr {
    // --- sources ---
    /// Named runtime input. Each unique name becomes one `Gadget::Ingest`.
    Input(String),
    /// Compile-time constant visible to the server (mask is always 0).
    PublicConst(u32),
    /// Compile-time constant hidden from the image by a fresh per-rotation mask.
    SecretConst(u32),

    // --- bitwise ---
    Xor(Rc<Expr>, Rc<Expr>),
    And(Rc<Expr>, Rc<Expr>),
    /// Lowered to `Xor(Xor(a,b), And(a,b))`.
    Or(Rc<Expr>, Rc<Expr>),
    /// Lowered to `XorConst(a, 0xffff_ffff)`.
    Not(Rc<Expr>),

    // --- arithmetic ---
    /// 32-bit wrapping addition. Lowered to `Builder::add32` (31 triples).
    Add(Rc<Expr>, Rc<Expr>),

    // --- shifts / rotations ---
    /// Left-rotation by a static amount. Free (mask rotates with value).
    Rotl(Rc<Expr>, u32),

    // --- control flow (if-converted) ---
    /// Bitwise select: `cond & on_true | ~cond & on_false`.
    /// Lowered to `Xor(on_false, And(cond, Xor(on_true, on_false)))`.
    /// `cond` is treated as a full 32-bit mask (all-ones = true, all-zeros =
    /// false); single-bit predicates should be broadcast before use.
    Mux {
        cond:     Rc<Expr>,
        on_true:  Rc<Expr>,
        on_false: Rc<Expr>,
    },
}

// Convenience constructors so callers don't have to write Rc::new everywhere.
impl Expr {
    pub fn input(name: &str) -> Rc<Self> {
        Rc::new(Self::Input(name.to_string()))
    }
    pub fn public_const(k: u32) -> Rc<Self> {
        Rc::new(Self::PublicConst(k))
    }
    pub fn secret_const(k: u32) -> Rc<Self> {
        Rc::new(Self::SecretConst(k))
    }
    pub fn xor(a: Rc<Self>, b: Rc<Self>) -> Rc<Self> {
        Rc::new(Self::Xor(a, b))
    }
    pub fn and(a: Rc<Self>, b: Rc<Self>) -> Rc<Self> {
        Rc::new(Self::And(a, b))
    }
    pub fn or(a: Rc<Self>, b: Rc<Self>) -> Rc<Self> {
        Rc::new(Self::Or(a, b))
    }
    pub fn not(a: Rc<Self>) -> Rc<Self> {
        Rc::new(Self::Not(a))
    }
    pub fn add(a: Rc<Self>, b: Rc<Self>) -> Rc<Self> {
        Rc::new(Self::Add(a, b))
    }
    pub fn rotl(a: Rc<Self>, r: u32) -> Rc<Self> {
        Rc::new(Self::Rotl(a, r))
    }
    pub fn mux(cond: Rc<Self>, on_true: Rc<Self>, on_false: Rc<Self>) -> Rc<Self> {
        Rc::new(Self::Mux { cond, on_true, on_false })
    }
}

// ---------------------------------------------------------------------------
// Transformations (stubs)
// ---------------------------------------------------------------------------

/// Evaluate any sub-expression whose leaves are all constants.
///
/// # Algorithm
///
/// Bottom-up recursive fold with a `HashMap<*const Expr, Rc<Expr>>` memo so
/// shared nodes are transformed exactly once.  At each node:
///
/// - If both children folded to constants, evaluate the operation in `u32`
///   arithmetic and return a new const node.
/// - Otherwise return a structurally-identical node whose children are the
///   already-folded sub-trees.
///
/// # Constant kinds
///
/// `PublicConst op PublicConst  → PublicConst`
/// `SecretConst op anything     → SecretConst`  (secret leaks through any op)
/// `PublicConst op SecretConst  → SecretConst`
///
/// # Short-circuit / identity rules (applied before recursing into children)
///
/// | Pattern | Result |
/// |---------|--------|
/// | `Xor(x, PublicConst(0))` | `x` |
/// | `And(x, PublicConst(0))` | `PublicConst(0)` |
/// | `And(x, PublicConst(0xffff_ffff))` | `x` |
/// | `Or(x, PublicConst(0xffff_ffff))` | `PublicConst(0xffff_ffff)` |
/// | `Or(x, PublicConst(0))` | `x` |
/// | `Not(PublicConst(k))` | `PublicConst(!k)` |
/// | `Rotl(PublicConst(k), r)` | `PublicConst(k.rotate_left(r))` |
pub fn constant_fold(_expr: &Rc<Expr>) -> Rc<Expr> {
    todo!()
}

/// Randomly reassociate XOR and AND trees.
///
/// # Algorithm
///
/// Bottom-up pass with memo.  At each `Xor` or `And` node, collect the
/// *flat operand list* for that operator by recursively peeling off nodes of
/// the same kind (e.g. `Xor(Xor(a, b), c)` → `[a, b, c]`).  Shuffle the
/// list with `rng`, then fold it back into a random left- or right-skewed
/// binary tree using `rng.gen_bool(0.5)` to pick left vs. right at each
/// step.  All other node kinds are traversed but not restructured.
///
/// # Why this changes topology
///
/// Two calls with different RNG states produce different tree shapes, which
/// lower to circuits with different gadget indices and pool layouts.  An
/// attacker comparing two images sees a different sub-graph structure even
/// though the function is identical.
///
/// # Sharing
///
/// Use a `HashMap<*const Expr, Rc<Expr>>` memo.  A shared node that appears
/// in multiple chains is collected into both — the memo ensures it is only
/// recursively transformed once, but it may appear at different positions in
/// the two shuffled operand lists.
pub fn reassociate(_expr: &Rc<Expr>, _rng: &mut impl rand::RngCore) -> Rc<Expr> {
    todo!()
}

/// Splice dead sub-expressions into the tree to pad the circuit with
/// AND-consuming noise an attacker cannot easily filter out.
///
/// # Decoy form
///
/// The canonical decoy is `Xor(e, Xor(And(p, q), And(p, q)))` which equals
/// `e ^ 0 = e` but adds two AND triples to the image.  `p` and `q` are
/// drawn from *existing* wires in the expression (collected by a pre-pass)
/// so the decoy operands are indistinguishable from real operands.
///
/// # Algorithm
///
/// 1. Pre-pass: collect a pool of candidate wire `Rc<Expr>` nodes (any node
///    that is not a constant).
/// 2. For each node in the tree (bottom-up, memo'd), with probability
///    `decoy_prob` splice in one decoy: choose `p` and `q` at random from
///    the candidate pool, construct `Xor(node, Xor(And(p,q), And(p,q)))`,
///    return that as the replacement.
/// 3. `decoy_prob` defaults to something like 0.15 so a typical circuit
///    grows by ~15–20% in AND-gate count.
///
/// # Interaction with other passes
///
/// Run `inject_decoys` *after* `reassociate` so decoy wires blend into the
/// already-shuffled structure, and run `constant_fold` *after* to eliminate
/// any trivial constant expressions the decoys might have introduced.
pub fn inject_decoys(_expr: &Rc<Expr>, _rng: &mut impl rand::RngCore) -> Rc<Expr> {
    todo!()
}

/// Randomly apply local algebraic identities at each node.
///
/// # Identities (each applied with independent probability `p ≈ 0.3`)
///
/// | Pattern | Replacement | Cost delta |
/// |---------|-------------|------------|
/// | `x` | `Not(Not(x))` | free (two XorConst) |
/// | `Not(Not(x))` | `x` | free |
/// | `Or(a, b)` | `Not(And(Not(a), Not(b)))` | same triples, different shape |
/// | `And(a, b)` | `Not(Or(Not(a), Not(b)))` | same triples, different shape |
/// | `Xor(a, b)` | `Not(Xor(Not(a), b))` | free |
///
/// # Algorithm
///
/// Recursive bottom-up pass with memo.  At each node, after transforming
/// children, pick a random subset of applicable identities and apply them.
/// Multiple identities can stack (e.g. introduce a double-NOT and then
/// De-Morgan the inner AND), producing deeper variation.
///
/// # Interaction with other passes
///
/// Run `constant_fold` after `apply_identities` to collapse any
/// `Not(PublicConst(k))` or `Xor(x, PublicConst(0))` nodes that the
/// identity rewrites may have introduced.
pub fn apply_identities(_expr: &Rc<Expr>, _rng: &mut impl rand::RngCore) -> Rc<Expr> {
    todo!()
}

/// Apply all structural transforms in sequence to produce a semantically
/// equivalent but structurally varied expression.
///
/// # Pipeline
///
/// ```text
/// constant_fold → reassociate → inject_decoys → apply_identities → constant_fold
/// ```
///
/// The leading `constant_fold` simplifies the input before randomization.
/// The trailing `constant_fold` cleans up any identity-introduced noise
/// (e.g. `Not(Not(x))`, `Xor(x, 0)`).
///
/// # Usage
///
/// ```ignore
/// let mut structure_rng = StdRng::seed_from_u64(structure_seed);
/// let rotated  = strong_rotate(&base_ast, &mut structure_rng);
/// let circuit  = lower_to_circuit(&rotated);
/// let vm       = ConcreteVm::from_circuit(&circuit, mask_seed);
/// let source   = emit_rust(&vm, "checksum");
/// ```
///
/// Use a different `structure_seed` for strong rotation (new circuit shape)
/// or the same `structure_seed` with a different `mask_seed` for cheap
/// rotation (same shape, fresh baked constants).
pub fn strong_rotate(_expr: &Rc<Expr>, _rng: &mut impl rand::RngCore) -> Rc<Expr> {
    todo!()
}
