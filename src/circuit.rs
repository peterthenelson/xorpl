//! Salt-free circuit: value graph, gadgets, and builder.
//!
//! `Circuit` is a topologically-ordered list of `Gadget`s describing the
//! mixing function F with no masks or secrets attached.  The server mirrors a
//! `Circuit` exactly and calls `Circuit::eval` to verify client checksums.
//!
//! `Builder` is the primary construction path.  Post-lowering circuit
//! transforms (see `circuit_transform`) also produce circuits by replaying
//! through a fresh `Builder`, so `validate` is called automatically.
//!
//! # Masking overview
//!
//! Each logical value `X` is stored at runtime as `X ^ m` where `m` is a
//! per-wire mask sampled during concretization (see `mask`).  Free ops
//! (XOR, rotation, NOT, AndConst, XorConst, Rotl) propagate masks
//! analytically.  Only bitwise AND is metered — it requires a fresh Beaver
//! triple per gate.  `Remask` re-randomises a wire's mask without changing
//! its value.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// ID types
// ---------------------------------------------------------------------------

pub type WireId = usize;
pub type GenId  = usize;

// ---------------------------------------------------------------------------
// Wire roles
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    Ingest,
    Egress,
    Internal,
}

// ---------------------------------------------------------------------------
// Gadget catalog
// ---------------------------------------------------------------------------

/// One entry per gadget kind.  Each carries its static parameters, input wire
/// IDs, any fresh-randomness generator IDs, and its output wire.
#[derive(Clone, Debug)]
pub enum Gadget {
    // --- sources ---
    PublicConst  { k: u32,                    out: WireId },
    SecretConst  { k: u32,  gen: GenId,       out: WireId },
    Ingest       { name: String, gen: GenId,  out: WireId },
    // --- free / linear ---
    Xor          { a: WireId, b: WireId,      out: WireId },
    XorConst     { a: WireId, k: u32,         out: WireId },
    AndConst     { a: WireId, k: u32,         out: WireId },
    Rotl         { a: WireId, r: u32,         out: WireId },
    // --- metered ---
    And          { a: WireId, b: WireId, gen: GenId, out: WireId },
    // --- utility ---
    Remask       { a: WireId,           gen: GenId, out: WireId },
    Egress       { a: WireId },
}

impl Gadget {
    pub fn kind(&self) -> &'static str {
        match self {
            Gadget::PublicConst { .. } => "PUBLIC_CONST",
            Gadget::SecretConst { .. } => "SECRET_CONST",
            Gadget::Ingest      { .. } => "INGEST",
            Gadget::Xor         { .. } => "XOR",
            Gadget::XorConst    { .. } => "XOR_CONST",
            Gadget::AndConst    { .. } => "AND_CONST",
            Gadget::Rotl        { .. } => "ROTL",
            Gadget::And         { .. } => "AND",
            Gadget::Remask      { .. } => "REMASK",
            Gadget::Egress      { .. } => "EGRESS",
        }
    }

    pub(crate) fn input_wires(&self) -> Vec<WireId> {
        match self {
            Gadget::Xor    { a, b, .. } | Gadget::And { a, b, .. } => vec![*a, *b],
            Gadget::XorConst { a, .. }
            | Gadget::AndConst { a, .. }
            | Gadget::Rotl   { a, .. }
            | Gadget::Remask { a, .. }
            | Gadget::Egress { a }      => vec![*a],
            Gadget::PublicConst { .. }
            | Gadget::SecretConst { .. }
            | Gadget::Ingest { .. }     => vec![],
        }
    }

    pub(crate) fn gen_refs(&self) -> Vec<GenId> {
        match self {
            Gadget::SecretConst { gen, .. }
            | Gadget::Ingest    { gen, .. }
            | Gadget::And       { gen, .. }
            | Gadget::Remask    { gen, .. } => vec![*gen],
            _ => vec![],
        }
    }

    pub fn out(&self) -> Option<WireId> {
        match self {
            Gadget::PublicConst { out, .. }
            | Gadget::SecretConst { out, .. }
            | Gadget::Ingest  { out, .. }
            | Gadget::Xor     { out, .. }
            | Gadget::XorConst { out, .. }
            | Gadget::AndConst { out, .. }
            | Gadget::Rotl    { out, .. }
            | Gadget::And     { out, .. }
            | Gadget::Remask  { out, .. } => Some(*out),
            Gadget::Egress { .. }         => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Generator {
    pub(crate) purpose: &'static str,
}

// ---------------------------------------------------------------------------
// Circuit
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Circuit {
    pub(crate) gadgets:    Vec<Gadget>,
    pub(crate) wires:      Vec<Wire>,
    pub(crate) generators: Vec<Generator>,
    pub(crate) egress:     WireId,
}

impl Circuit {
    /// Stable structural fingerprint of the circuit — a hash of gadget types,
    /// wire topology, and constants.  Identical circuits always produce the
    /// same tag; structurally distinct circuits almost certainly differ.
    ///
    /// The tag is used as a rotation discriminant: the browser includes it in
    /// every event report, and the server uses it to select the matching
    /// verifier function.  It is NOT a security primitive — just a version key.
    pub fn fingerprint(&self) -> u32 {
        const OFFSET: u64 = 0xcbf29ce484222325;
        const PRIME:  u64 = 0x100000001b3;

        fn mix(mut h: u64, v: u64) -> u64 {
            for b in v.to_le_bytes() {
                h ^= b as u64;
                h  = h.wrapping_mul(PRIME);
            }
            h
        }

        let mut h = OFFSET;
        for g in &self.gadgets {
            h = match g {
                Gadget::PublicConst { k, out } =>
                    mix(mix(mix(h, 0), *k as u64), *out as u64),
                Gadget::SecretConst { k, out, .. } =>
                    mix(mix(mix(h, 1), *k as u64), *out as u64),
                Gadget::Ingest { name, out, .. } => {
                    let mut h = mix(h, 2);
                    for b in name.bytes() { h = mix(h, b as u64); }
                    mix(h, *out as u64)
                }
                Gadget::Xor { a, b, out } =>
                    mix(mix(mix(mix(h, 3), *a as u64), *b as u64), *out as u64),
                Gadget::XorConst { a, k, out } =>
                    mix(mix(mix(mix(h, 4), *a as u64), *k as u64), *out as u64),
                Gadget::AndConst { a, k, out } =>
                    mix(mix(mix(mix(h, 5), *a as u64), *k as u64), *out as u64),
                Gadget::Rotl { a, r, out } =>
                    mix(mix(mix(mix(h, 6), *a as u64), *r as u64), *out as u64),
                Gadget::And { a, b, out, .. } =>
                    mix(mix(mix(mix(h, 7), *a as u64), *b as u64), *out as u64),
                Gadget::Remask { a, out, .. } =>
                    mix(mix(mix(h, 8), *a as u64), *out as u64),
                Gadget::Egress { a } =>
                    mix(mix(h, 9), *a as u64),
            };
        }
        let (lo, hi) = (h as u32, (h >> 32) as u32);
        lo ^ hi
    }

    /// Evaluate the unmasked function F (server-side spec).
    pub(crate) fn eval(&self, inputs: &HashMap<String, u32>) -> HashMap<WireId, u32> {
        let mut v: HashMap<WireId, u32> = HashMap::new();
        for g in &self.gadgets {
            match g {
                Gadget::PublicConst { k, out }     => { v.insert(*out, *k); }
                Gadget::SecretConst { k, out, .. } => { v.insert(*out, *k); }
                Gadget::Ingest { name, out, .. }   => { v.insert(*out, inputs[name]); }
                Gadget::Xor { a, b, out }          => { v.insert(*out, v[a] ^ v[b]); }
                Gadget::XorConst { a, k, out }     => { v.insert(*out, v[a] ^ *k); }
                Gadget::AndConst { a, k, out }     => { v.insert(*out, v[a] & *k); }
                Gadget::Rotl { a, r, out }         => { v.insert(*out, v[a].rotate_left(*r)); }
                Gadget::And { a, b, out, .. }      => { v.insert(*out, v[a] & v[b]); }
                Gadget::Remask { a, out, .. }      => { v.insert(*out, v[a]); }
                Gadget::Egress { .. }              => {}
            }
        }
        v
    }

    /// Full structural validation.
    ///
    /// Checks: egress wire role, exactly one Egress gadget, single-assignment,
    /// topological order (inputs written before read), GenId uniqueness
    /// (no triple reuse), and all ID ranges.
    ///
    /// `Builder::build` calls this and panics on failure.  Circuit transforms
    /// that construct a `Circuit` directly should call it too.
    pub(crate) fn validate(&self) -> Result<(), String> {
        let nw = self.wires.len();
        let ng = self.generators.len();

        if self.egress >= nw {
            return Err(format!("egress={} out of range ({nw} wires)", self.egress));
        }
        if self.wires[self.egress] != Wire::Egress {
            return Err(format!(
                "egress={} has role {:?}, expected Egress",
                self.egress, self.wires[self.egress]
            ));
        }

        let mut written:    HashSet<WireId> = HashSet::new();
        let mut used_gens:  HashSet<GenId>  = HashSet::new();
        let mut egress_count = 0usize;

        for (idx, g) in self.gadgets.iter().enumerate() {
            let label = || format!("gadget[{idx}] {}", g.kind());

            if matches!(g, Gadget::Egress { .. }) {
                egress_count += 1;
            }

            if let Some(out) = g.out() {
                if out >= nw {
                    return Err(format!("{}: output WireId {out} out of range", label()));
                }
                if !written.insert(out) {
                    return Err(format!("{}: output WireId {out} already written", label()));
                }
            }

            for a in g.input_wires() {
                if a >= nw {
                    return Err(format!("{}: input WireId {a} out of range", label()));
                }
                if matches!(g, Gadget::Egress { .. }) {
                    if a != self.egress {
                        return Err(format!("{}: reads wire {a}, expected egress {}", label(), self.egress));
                    }
                } else if self.wires[a] == Wire::Egress {
                    return Err(format!("{}: input WireId {a} has role Egress", label()));
                }
                if !written.contains(&a) {
                    return Err(format!("{}: input WireId {a} read before written (topo order)", label()));
                }
            }

            for gen in g.gen_refs() {
                if gen >= ng {
                    return Err(format!("{}: GenId {gen} out of range", label()));
                }
                if !used_gens.insert(gen) {
                    return Err(format!("{}: GenId {gen} already used (triple reuse)", label()));
                }
            }
        }

        if egress_count != 1 {
            return Err(format!("expected exactly 1 Egress gadget, found {egress_count}"));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

pub struct Builder {
    wires:      Vec<Wire>,
    gadgets:    Vec<Gadget>,
    generators: Vec<Generator>,
}

impl Builder {
    pub fn new() -> Self {
        Self { wires: vec![], gadgets: vec![], generators: vec![] }
    }

    fn alloc_wire(&mut self, role: Wire) -> WireId {
        let id = self.wires.len();
        self.wires.push(role);
        id
    }

    fn alloc_gen(&mut self, purpose: &'static str) -> GenId {
        let id = self.generators.len();
        self.generators.push(Generator { purpose });
        id
    }

    pub fn ingest(&mut self, name: &str) -> WireId {
        let gen = self.alloc_gen("ingest");
        let out = self.alloc_wire(Wire::Ingest);
        self.gadgets.push(Gadget::Ingest { name: name.to_string(), gen, out });
        out
    }

    pub fn public_const(&mut self, k: u32) -> WireId {
        let out = self.alloc_wire(Wire::Internal);
        self.gadgets.push(Gadget::PublicConst { k, out });
        out
    }

    pub fn secret_const(&mut self, k: u32) -> WireId {
        let gen = self.alloc_gen("secret const");
        let out = self.alloc_wire(Wire::Internal);
        self.gadgets.push(Gadget::SecretConst { k, gen, out });
        out
    }

    pub fn xor(&mut self, a: WireId, b: WireId) -> WireId {
        let out = self.alloc_wire(Wire::Internal);
        self.gadgets.push(Gadget::Xor { a, b, out });
        out
    }

    pub fn xor_const(&mut self, a: WireId, k: u32) -> WireId {
        let out = self.alloc_wire(Wire::Internal);
        self.gadgets.push(Gadget::XorConst { a, k, out });
        out
    }

    pub fn and_const(&mut self, a: WireId, k: u32) -> WireId {
        let out = self.alloc_wire(Wire::Internal);
        self.gadgets.push(Gadget::AndConst { a, k, out });
        out
    }

    pub fn rotl(&mut self, a: WireId, r: u32) -> WireId {
        let out = self.alloc_wire(Wire::Internal);
        self.gadgets.push(Gadget::Rotl { a, r, out });
        out
    }

    pub fn and(&mut self, a: WireId, b: WireId) -> WireId {
        let gen = self.alloc_gen("AND");
        let out = self.alloc_wire(Wire::Internal);
        self.gadgets.push(Gadget::And { a, b, gen, out });
        out
    }

    pub fn remask(&mut self, a: WireId) -> WireId {
        let gen = self.alloc_gen("remask");
        let out = self.alloc_wire(Wire::Internal);
        self.gadgets.push(Gadget::Remask { a, gen, out });
        out
    }

    /// 32-bit wrapping addition using the word-level generate optimization.
    /// Cost: 31 triples (1 for generate bits, 30 for carry-propagate chain).
    pub fn add32(&mut self, a: WireId, b: WireId) -> WireId {
        let g_word = self.and(a, b);
        let p_word = self.xor(a, b);

        let s_0 = self.and_const(p_word, 1);
        let g_0 = self.and_const(g_word, 1);
        let c_1 = self.rotl(g_0, 1);

        let mut carry = c_1;
        let mut sum   = s_0;

        for i in 1u32..=31 {
            let mask  = 1u32 << i;
            let p_i   = self.and_const(p_word, mask);
            let s_i   = self.xor(p_i, carry);
            sum       = self.xor(sum, s_i);
            if i < 31 {
                let g_i        = self.and_const(g_word, mask);
                let p_and_c    = self.and(p_i, carry);
                let carry_at_i = self.xor(g_i, p_and_c);
                carry          = self.rotl(carry_at_i, 1);
            }
        }

        sum
    }

    /// Finalise the circuit.  Calls `validate` and panics on failure — a bug
    /// here is a programming error, not a runtime condition.
    pub fn build(mut self, result: WireId) -> Circuit {
        self.wires[result] = Wire::Egress;
        self.gadgets.push(Gadget::Egress { a: result });
        let c = Circuit {
            egress:     result,
            gadgets:    self.gadgets,
            wires:      self.wires,
            generators: self.generators,
        };
        c.validate().expect("Builder::build produced an invalid circuit");
        c
    }
}

// ---------------------------------------------------------------------------
// Example circuits (used by demo and tests)
// ---------------------------------------------------------------------------

const DEMO_CONST: u32 = 0x9e37_79b9;

pub(crate) fn build_example() -> Circuit {
    let mut b  = Builder::new();
    let wa     = b.ingest("a");
    let wb     = b.ingest("b");
    let wc     = b.secret_const(DEMO_CONST);
    let xor_ab = b.xor(wa, wb);
    let and_ab = b.and(wa, wb);
    let or_ab  = b.xor(xor_ab, and_ab);
    let xored  = b.xor(or_ab, wc);
    let result = b.rotl(xored, 5);
    b.build(result)
}

pub(crate) fn build_add32_example() -> Circuit {
    let mut b  = Builder::new();
    let wa     = b.ingest("a");
    let wb     = b.ingest("b");
    let result = b.add32(wa, wb);
    b.build(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn no_triple_reuse() {
        let c = build_example();
        let and_gens: Vec<GenId> = c.gadgets.iter()
            .filter_map(|g| if let Gadget::And { gen, .. } = g { Some(*gen) } else { None })
            .collect();
        let unique: HashSet<GenId> = and_gens.iter().copied().collect();
        assert_eq!(unique.len(), and_gens.len(), "AND gates share a generator");
    }

    #[test]
    fn add32_uses_31_triples() {
        let c = build_add32_example();
        let count = c.gadgets.iter().filter(|g| matches!(g, Gadget::And { .. })).count();
        assert_eq!(count, 31, "ADD32 triple count");
    }

    #[test]
    fn fingerprint_stable_for_same_circuit() {
        let c1 = build_example();
        let c2 = build_example();
        assert_eq!(c1.fingerprint(), c2.fingerprint());
    }

    #[test]
    fn fingerprint_differs_for_different_circuits() {
        let c_or_rotl = build_example();
        let c_add32   = build_add32_example();
        assert_ne!(c_or_rotl.fingerprint(), c_add32.fingerprint());
    }

    #[test]
    fn fingerprint_changes_after_strong_rotate() {
        use rand::SeedableRng;
        use crate::expr::Expr;
        use crate::expr_transform::strong_rotate;
        use crate::lower::lower_to_circuit;

        let a = Expr::input("a");
        let b = Expr::input("b");
        let c = Expr::secret_const(0x9e37_79b9);
        let expr = Expr::rotl(Expr::xor(Expr::or(a, b), c), 5);

        let mut rng_a = rand::rngs::StdRng::seed_from_u64(1);
        let mut rng_b = rand::rngs::StdRng::seed_from_u64(2);

        let ca = lower_to_circuit(&strong_rotate(&expr, &mut rng_a));
        let cb = lower_to_circuit(&strong_rotate(&expr, &mut rng_b));
        assert_ne!(ca.fingerprint(), cb.fingerprint(),
            "different strong_rotate seeds should (almost certainly) yield different fingerprints");
    }
}
