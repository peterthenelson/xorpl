//! Expression tree for the mixing function F.
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

use std::rc::Rc;

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
