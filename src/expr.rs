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

use std::collections::{HashMap, HashSet};
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

// ---------------------------------------------------------------------------
// Expression digest
// ---------------------------------------------------------------------------

/// Compute a stable digest of the expression DAG.
///
/// The digest is derived from a canonical byte serialization of the expression
/// tree (post-order, deduplicating shared nodes by pointer identity).  With
/// `key = None` the result is plain SHA-256; with `key = Some(k)` it is
/// HMAC-SHA-256(k, serialized), which prevents an observer from verifying
/// guesses about the original expression from the embedded constant alone.
///
/// The digest is stable across any obfuscation transforms (cheap or strong
/// rotation) because it is computed from the original expression before any
/// transforms are applied.
pub fn expr_digest(root: &Rc<Expr>, key: Option<&[u8]>) -> [u8; 32] {
    // Collect nodes in post-order (children before parents), deduplicating by
    // Rc pointer identity so shared sub-expressions appear exactly once.
    let mut order: Vec<Rc<Expr>> = Vec::new();
    let mut visited: HashSet<*const Expr> = HashSet::new();
    let mut stack: Vec<(Rc<Expr>, bool)> = vec![(Rc::clone(root), false)];

    while let Some((node, children_done)) = stack.pop() {
        if children_done {
            order.push(node);
            continue;
        }
        let ptr = Rc::as_ptr(&node);
        if !visited.insert(ptr) {
            continue;
        }
        // Re-push this node for post-processing, then push children (reversed
        // so the first child is processed first).
        stack.push((Rc::clone(&node), true));
        match node.as_ref() {
            Expr::Xor(a, b) | Expr::And(a, b) | Expr::Or(a, b) | Expr::Add(a, b) => {
                stack.push((Rc::clone(b), false));
                stack.push((Rc::clone(a), false));
            }
            Expr::Not(a) | Expr::Rotl(a, _) => {
                stack.push((Rc::clone(a), false));
            }
            Expr::Mux { cond, on_true, on_false } => {
                stack.push((Rc::clone(on_false), false));
                stack.push((Rc::clone(on_true), false));
                stack.push((Rc::clone(cond), false));
            }
            Expr::Input(_) | Expr::PublicConst(_) | Expr::SecretConst(_) => {}
        }
    }

    // Build index map so child references can be encoded as positions.
    let index: HashMap<*const Expr, u32> = order.iter()
        .enumerate()
        .map(|(i, e)| (Rc::as_ptr(e), i as u32))
        .collect();

    // Serialize each node: [type_tag, ...fields].  Child references are
    // encoded as their 4-byte LE index in topological order.
    let mut bytes: Vec<u8> = Vec::new();
    for node in &order {
        match node.as_ref() {
            Expr::Input(name) => {
                bytes.push(0x01);
                bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
                bytes.extend_from_slice(name.as_bytes());
            }
            Expr::PublicConst(k) => {
                bytes.push(0x02);
                bytes.extend_from_slice(&k.to_le_bytes());
            }
            Expr::SecretConst(k) => {
                bytes.push(0x03);
                bytes.extend_from_slice(&k.to_le_bytes());
            }
            Expr::Xor(a, b) => {
                bytes.push(0x04);
                bytes.extend_from_slice(&index[&Rc::as_ptr(a)].to_le_bytes());
                bytes.extend_from_slice(&index[&Rc::as_ptr(b)].to_le_bytes());
            }
            Expr::And(a, b) => {
                bytes.push(0x05);
                bytes.extend_from_slice(&index[&Rc::as_ptr(a)].to_le_bytes());
                bytes.extend_from_slice(&index[&Rc::as_ptr(b)].to_le_bytes());
            }
            Expr::Or(a, b) => {
                bytes.push(0x06);
                bytes.extend_from_slice(&index[&Rc::as_ptr(a)].to_le_bytes());
                bytes.extend_from_slice(&index[&Rc::as_ptr(b)].to_le_bytes());
            }
            Expr::Not(a) => {
                bytes.push(0x07);
                bytes.extend_from_slice(&index[&Rc::as_ptr(a)].to_le_bytes());
            }
            Expr::Add(a, b) => {
                bytes.push(0x08);
                bytes.extend_from_slice(&index[&Rc::as_ptr(a)].to_le_bytes());
                bytes.extend_from_slice(&index[&Rc::as_ptr(b)].to_le_bytes());
            }
            Expr::Rotl(a, r) => {
                bytes.push(0x09);
                bytes.extend_from_slice(&index[&Rc::as_ptr(a)].to_le_bytes());
                bytes.extend_from_slice(&r.to_le_bytes());
            }
            Expr::Mux { cond, on_true, on_false } => {
                bytes.push(0x0a);
                bytes.extend_from_slice(&index[&Rc::as_ptr(cond)].to_le_bytes());
                bytes.extend_from_slice(&index[&Rc::as_ptr(on_true)].to_le_bytes());
                bytes.extend_from_slice(&index[&Rc::as_ptr(on_false)].to_le_bytes());
            }
        }
    }

    use sha2::Digest as _;
    match key {
        None => {
            sha2::Sha256::digest(&bytes).into()
        }
        Some(k) => {
            use hmac::Mac as _;
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(k)
                .expect("HMAC accepts any key length");
            mac.update(&bytes);
            mac.finalize().into_bytes().into()
        }
    }
}
