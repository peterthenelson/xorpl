//! Obfuscated-VM compiler — concretization skeleton (Rust port).
//!
//! Two layers, as in the TypeScript original:
//!   1. A salt-free VALUE GRAPH (`Circuit`): what `F` computes. The server
//!      mirrors this exactly (masks cancel, so value semantics are identical).
//!   2. CONCRETIZATION: given a seed, decorate every wire with a concrete mask
//!      and emit the baked constants. Rotating the VM = re-run with a new seed.
//!
//! Every gadget has parallel transfer functions:
//!   value(...)  : the spec                 -> `eval_values` (also the server)
//!   mask(...)   : how masks flow           -> the body of `concretize`
//!   constants() : baked image constants    -> the body of `concretize`
//!   lower(...)  : masked-register run       -> `run_masked` (the verifier)
//!
//! `run_masked` proves the scheme closes: every wire's register holds
//! value ^ mask, and egress reveals exactly the plaintext the server computes.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

// ---------- ids ----------
pub type WireId = usize;
pub type GenId = usize;

// ---------- wires ----------
// A wire carries a VALUE (conceptual) and, after concretize, a MASK. Its
// register content at runtime is always value ^ mask. The mask is NOT stored
// on the wire — it lives in a side map, keeping the value graph salt-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    Ingest,
    Egress,
    Internal,
}

// ---------- gadgets ----------
// One variant per catalog entry. Each carries its static params, input wire
// ids, the GenIds of any FRESH randomness it introduces, and its output wire.
#[derive(Clone, Debug)]
pub enum Gadget {
    // sources
    PublicConst { k: u32, out: WireId },                 // mask 0
    SecretConst { k: u32, gen: GenId, out: WireId },     // obscured program const
    Ingest { name: String, gen: GenId, out: WireId },    // runtime input, masked on entry
    // free / linear (mask is a fixed image of input masks)
    Xor { a: WireId, b: WireId, out: WireId },
    XorConst { a: WireId, k: u32, out: WireId }, // mask unchanged
    AndConst { a: WireId, k: u32, out: WireId }, // mask &= k
    Rotl { a: WireId, r: u32, out: WireId },     // mask rotates with value
    // metered (must mint a fresh output mask) — the ONLY triple consumer
    And { a: WireId, b: WireId, gen: GenId, out: WireId },
    // utility
    Remask { a: WireId, gen: GenId, out: WireId }, // re-randomize the mask
    Egress { a: WireId },                          // unmask & reveal
}

impl Gadget {
    pub fn kind(&self) -> &'static str {
        match self {
            Gadget::PublicConst { .. } => "PUBLIC_CONST",
            Gadget::SecretConst { .. } => "SECRET_CONST",
            Gadget::Ingest { .. } => "INGEST",
            Gadget::Xor { .. } => "XOR",
            Gadget::XorConst { .. } => "XOR_CONST",
            Gadget::AndConst { .. } => "AND_CONST",
            Gadget::Rotl { .. } => "ROTL",
            Gadget::And { .. } => "AND",
            Gadget::Remask { .. } => "REMASK",
            Gadget::Egress { .. } => "EGRESS",
        }
    }

    pub(crate) fn input_wires(&self) -> Vec<WireId> {
        match self {
            Gadget::Xor { a, b, .. } | Gadget::And { a, b, .. } => vec![*a, *b],
            Gadget::XorConst { a, .. }
            | Gadget::AndConst { a, .. }
            | Gadget::Rotl { a, .. }
            | Gadget::Remask { a, .. }
            | Gadget::Egress { a } => vec![*a],
            Gadget::PublicConst { .. }
            | Gadget::SecretConst { .. }
            | Gadget::Ingest { .. } => vec![],
        }
    }

    fn gen_refs(&self) -> Vec<GenId> {
        match self {
            Gadget::SecretConst { gen, .. }
            | Gadget::Ingest { gen, .. }
            | Gadget::And { gen, .. }
            | Gadget::Remask { gen, .. } => vec![*gen],
            _ => vec![],
        }
    }

    /// Output wire, if any (Egress has none).
    pub fn out(&self) -> Option<WireId> {
        match self {
            Gadget::PublicConst { out, .. }
            | Gadget::SecretConst { out, .. }
            | Gadget::Ingest { out, .. }
            | Gadget::Xor { out, .. }
            | Gadget::XorConst { out, .. }
            | Gadget::AndConst { out, .. }
            | Gadget::Rotl { out, .. }
            | Gadget::And { out, .. }
            | Gadget::Remask { out, .. } => Some(*out),
            Gadget::Egress { .. } => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Generator {
    // GenId is the generator's index in Circuit.generators — not stored redundantly here.
    purpose: &'static str, // for the registry / debugging
}

#[derive(Clone, Debug)]
pub struct Circuit {
    pub(crate) gadgets: Vec<Gadget>, // topological order
    wires: Vec<Wire>,                // indexed by WireId
    generators: Vec<Generator>,
    pub(crate) egress: WireId,
}

impl Circuit {
    pub(crate) fn eval(&self, inputs: &HashMap<String, u32>) -> HashMap<WireId, u32> {
        let mut v: HashMap<WireId, u32> = HashMap::new();
        for g in &self.gadgets {
            match g {
                Gadget::PublicConst { k, out } => {
                    v.insert(*out, *k);
                }
                Gadget::SecretConst { k, out, .. } => {
                    v.insert(*out, *k);
                }
                Gadget::Ingest { name, out, .. } => {
                    v.insert(*out, inputs[name]);
                }
                Gadget::Xor { a, b, out } => {
                    let val = v[a] ^ v[b];
                    v.insert(*out, val);
                }
                Gadget::XorConst { a, k, out } => {
                    let val = v[a] ^ *k;
                    v.insert(*out, val);
                }
                Gadget::AndConst { a, k, out } => {
                    let val = v[a] & *k;
                    v.insert(*out, val);
                }
                Gadget::Rotl { a, r, out } => {
                    let val = v[a].rotate_left(*r);
                    v.insert(*out, val);
                }
                Gadget::And { a, b, out, .. } => {
                    let val = v[a] & v[b];
                    v.insert(*out, val);
                }
                Gadget::Remask { a, out, .. } => {
                    let val = v[a];
                    v.insert(*out, val);
                }
                Gadget::Egress { .. } => {}
            }
        }
        v
    }

    /// Full structural check for a `Circuit`.
    ///
    /// Verifies:
    /// - The egress WireId is in range and has the Egress role.
    /// - Exactly one `Gadget::Egress` exists.
    /// - Every gadget's output WireId is in range and written at most once
    ///   (single-assignment).
    /// - Every gadget's input WireIds are in range, not Egress-role wires
    ///   (unless it is the Egress gadget), and already written by an earlier
    ///   gadget (topological order).
    /// - Every GenId reference is in range and used by at most one gadget
    ///   (uniqueness — no triple reuse).
    ///
    /// `Builder::build` calls this and panics on failure.  Circuit transforms
    /// that construct a `Circuit` directly should call it too — it is the
    /// complete safety net for any construction path, not a Builder-only concern.
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

        let mut written: HashSet<WireId> = HashSet::new();
        let mut used_gens: HashSet<GenId> = HashSet::new();
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
                    return Err(format!("{}: output WireId {out} already written by an earlier gadget", label()));
                }
            }

            for a in g.input_wires() {
                if a >= nw {
                    return Err(format!("{}: input WireId {a} out of range", label()));
                }
                if matches!(g, Gadget::Egress { .. }) {
                    if a != self.egress {
                        return Err(format!("{}: reads wire {a}, expected circuit egress {}", label(), self.egress));
                    }
                } else if self.wires[a] == Wire::Egress {
                    return Err(format!("{}: input WireId {a} has role Egress", label()));
                }
                if !written.contains(&a) {
                    return Err(format!("{}: input WireId {a} read before it is written (topological order violation)", label()));
                }
            }

            for gen in g.gen_refs() {
                if gen >= ng {
                    return Err(format!("{}: GenId {gen} out of range ({ng} generators)", label()));
                }
                if !used_gens.insert(gen) {
                    return Err(format!("{}: GenId {gen} already used by an earlier gadget (triple reuse)", label()));
                }
            }
        }

        if egress_count != 1 {
            return Err(format!("expected exactly 1 Egress gadget, found {egress_count}"));
        }

        Ok(())
    }
}

// ---------- circuit builder ----------
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
    ///
    /// Cost: 1 triple for `G = A & B` (all 32 generate bits at once), plus
    /// 30 triples for the carry-propagate chain (bits 1–30; bit 0 has carry-in
    /// 0 so it's free, and bit 31 needs no carry-out).  Total: 31 triples.
    ///
    /// Each carry `c[i]` lives at bit position `i` in a u32 word (all other
    /// bits zero).  `rotl(..., 1)` advances it to position `i+1`.  Because
    /// `p[i]` and `c[i]` each occupy only bit `i`, their AND is a one-bit
    /// operation even though the gadget works on the full word.
    pub fn add32(&mut self, a: WireId, b: WireId) -> WireId {
        let g_word = self.and(a, b);    // g_word[i] = a[i] & b[i] for all 32 bits
        let p_word = self.xor(a, b);    // p_word[i] = a[i] ^ b[i] for all 32 bits

        // Bit 0: carry-in is 0, so s[0] = p[0] and c[1] = g[0].
        let s_0 = self.and_const(p_word, 1);
        let g_0 = self.and_const(g_word, 1);
        let c_1 = self.rotl(g_0, 1);           // c[1] lives at bit position 1

        let mut carry = c_1;  // c[i] at bit position i
        let mut sum   = s_0;  // accumulated sum, one settled bit per position

        for i in 1u32..=31 {
            let mask = 1u32 << i;
            let p_i = self.and_const(p_word, mask);   // p[i] at bit i, rest 0
            let s_i = self.xor(p_i, carry);           // s[i] = p[i] ^ c[i]
            sum = self.xor(sum, s_i);

            if i < 31 {
                // c[i+1] = g[i] ^ (p[i] & c[i])
                let g_i       = self.and_const(g_word, mask);
                let p_and_c   = self.and(p_i, carry);         // p[i] & c[i], at bit i
                let carry_at_i = self.xor(g_i, p_and_c);
                carry = self.rotl(carry_at_i, 1);             // advance to bit i+1
            }
        }

        sum
    }

    /// Finalise the circuit, marking `result` as the egress wire.
    ///
    /// This is the sole intended way to produce a `Circuit`. All structural
    /// invariants (wire/generator ID ranges, single-write rule, egress
    /// constraints) are enforced here; the panic is intentional — a bug in
    /// a builder call is a programming error, not a runtime condition.
    pub fn build(mut self, result: WireId) -> Circuit {
        self.wires[result] = Wire::Egress;
        self.gadgets.push(Gadget::Egress { a: result });
        let c = Circuit {
            egress: result,
            gadgets: self.gadgets,
            wires: self.wires,
            generators: self.generators,
        };
        c.validate().expect("Builder::build produced an invalid circuit");
        c
    }
}

// ---------- what gets baked into a concrete VM image ----------
#[derive(Clone, Debug)]
pub struct BakedGadget {
    idx: usize,
    kind: &'static str,
    pub(crate) consts: Vec<u32>, // constant-pool entries this gadget references
    note: String,                // human-readable, for the demo dump
}

#[derive(Debug)]
pub struct ConcreteVm {
    pub(crate) circuit: Circuit,
    seed: u64,
    pub(crate) emit_seed: u64, // seeds the register allocator's shuffle in emit_rust
    pub(crate) baked: Vec<BakedGadget>,
    pub(crate) masks: HashMap<WireId, u32>, // NOT shipped — debug / sanity only
    gen_values: HashMap<GenId, u32>, // the sampled randomness (the rotation key)
}

fn hx32(x: u32) -> String {
    format!("0x{:08x}", x)
}

fn hx64(x: u64) -> String {
    format!("0x{:016x}", x)
}

impl ConcreteVm {
    // =====================================================================
    // CONCRETIZE: mask propagation + constant emission, in one topo pass.
    // =====================================================================
    pub fn from_circuit(c: &Circuit, seed: u64) -> ConcreteVm {
        c.validate().expect("invalid circuit");
        let mut rng = StdRng::seed_from_u64(seed);

        // Sample the emit seed before anything else so it is independent of
        // mask-generation details (number of generators, retry count, etc.).
        let emit_seed: u64 = rng.random();

        // Collect the generator ids for secret-carrying wires (Ingest and
        // SecretConst).  Their masks must be non-zero — a zero mask would
        // expose the secret value in the baked constants or registers.
        let secret_gens: Vec<GenId> = c.gadgets.iter()
            .filter_map(|g| match g {
                Gadget::Ingest { gen, .. } | Gadget::SecretConst { gen, .. } => Some(*gen),
                _ => None,
            })
            .collect();

        // Sample every generator, retrying until all secret masks are non-zero.
        // The probability of needing a retry is at most |secret_gens| / 2^32
        // per attempt, so this loop almost always terminates in one iteration.
        let gen_values: HashMap<GenId, u32> = loop {
            let mut gv: HashMap<GenId, u32> = HashMap::new();
            for (id, _) in c.generators.iter().enumerate() {
                gv.insert(id, rng.random());
            }
            if secret_gens.iter().all(|g| gv[g] != 0) {
                break gv;
            }
        };

        let mut masks: HashMap<WireId, u32> = HashMap::new();
        let mut baked: Vec<BakedGadget> = Vec::new();

        for (idx, g) in c.gadgets.iter().enumerate() {
            let kind = g.kind();
            let (consts, note): (Vec<u32>, String) = match g {
                Gadget::PublicConst { k, out } => {
                    masks.insert(*out, 0);
                    (vec![*k], format!("public {}", hx32(*k)))
                }
                Gadget::SecretConst { k, gen, out } => {
                    let m = gen_values[gen];
                    masks.insert(*out, m); // value k hidden under mask m...
                    (vec![*k ^ m], format!("bake k^mask (mask=gen#{})", gen)) // ...via baked k^m
                }
                Gadget::Ingest { name, gen, out } => {
                    let m = gen_values[gen];
                    masks.insert(*out, m); // masked the instant it enters
                    (
                        vec![m],
                        format!("XOR runtime \"{}\" with ingest mask gen#{}", name, gen),
                    )
                }
                Gadget::Xor { a, b, out } => {
                    let m = masks[a] ^ masks[b]; // same fn as value
                    masks.insert(*out, m);
                    (vec![], "free".to_string())
                }
                Gadget::XorConst { a, k, out } => {
                    let m = masks[a]; // public k: mask unchanged
                    masks.insert(*out, m);
                    (vec![*k], "free; mask unchanged".to_string())
                }
                Gadget::AndConst { a, k, out } => {
                    let m = masks[a] & *k; // mask &= k
                    masks.insert(*out, m);
                    (vec![*k], "free; mask &= k".to_string())
                }
                Gadget::Rotl { a, r, out } => {
                    let m = masks[a].rotate_left(*r); // mask rotates with the value
                    masks.insert(*out, m);
                    (vec![], "free; mask rotated".to_string())
                }
                Gadget::And { a, b, gen, out } => {
                    // the one nonlinear gate: mint a fresh output mask, tailor the
                    // triple to whatever masks the operands already carry.
                    let ma = masks[a];
                    let mb = masks[b];
                    let mz = gen_values[gen];
                    masks.insert(*out, mz);
                    let t = (ma & mb) ^ mz; // triple, with output mask folded in
                    (
                        vec![t, ma, mb],
                        format!("triple [T, ma, mb], out mask=gen#{}", gen),
                    )
                }
                Gadget::Remask { a, gen, out } => {
                    let target = gen_values[gen];
                    let delta = masks[a] ^ target;
                    masks.insert(*out, target);
                    (vec![delta], format!("XOR remask delta -> gen#{}", gen))
                }
                Gadget::Egress { a } => {
                    // the one intended reveal: unmask delta = mask of input
                    (vec![masks[a]], "unmask & reveal".to_string())
                }
            };
            baked.push(BakedGadget {
                idx,
                kind,
                consts,
                note,
            });
        }

        ConcreteVm {
            circuit: c.clone(),
            seed,
            emit_seed,
            baked,
            masks,
            gen_values,
        }
    }

    // =====================================================================
    // MASKED RUN (the actual obfuscated VM). Only baked constants + inputs.
    // This is the proof that the masking closes.
    // =====================================================================
    pub(crate) fn eval(
        &self,
        inputs: &HashMap<String, u32>,
    ) -> (HashMap<WireId, u32>, u32) {
        let mut regs: HashMap<WireId, u32> = HashMap::new();
        let mut revealed: u32 = 0;

        for (idx, g) in self.circuit.gadgets.iter().enumerate() {
            let k = &self.baked[idx].consts;
            match g {
                Gadget::PublicConst { out, .. } => {
                    regs.insert(*out, k[0]);
                }
                Gadget::SecretConst { out, .. } => {
                    regs.insert(*out, k[0]); // k^mask, already baked
                }
                Gadget::Ingest { name, out, .. } => {
                    let val = inputs[name] ^ k[0];
                    regs.insert(*out, val);
                }
                Gadget::Xor { a, b, out } => {
                    let val = regs[a] ^ regs[b];
                    regs.insert(*out, val);
                }
                Gadget::XorConst { a, out, .. } => {
                    let val = regs[a] ^ k[0];
                    regs.insert(*out, val);
                }
                Gadget::AndConst { a, out, .. } => {
                    let val = regs[a] & k[0];
                    regs.insert(*out, val);
                }
                Gadget::Rotl { a, r, out } => {
                    let val = regs[a].rotate_left(*r);
                    regs.insert(*out, val);
                }
                Gadget::And { a, b, out, .. } => {
                    // z = T ^ (x & mb) ^ (y & ma) ^ (x & y)  ==  (X & Y) ^ mz
                    let (t, ma, mb) = (k[0], k[1], k[2]);
                    let ra = regs[a];
                    let rb = regs[b];
                    let mut z = t;
                    z ^= ra & mb; // AND with constant — free
                    z ^= rb & ma; // AND with constant — free
                    z ^= ra & rb; // the one real masked AND
                    regs.insert(*out, z);
                }
                Gadget::Remask { a, out, .. } => {
                    let val = regs[a] ^ k[0];
                    regs.insert(*out, val);
                }
                Gadget::Egress { a } => {
                    revealed = regs[a] ^ k[0]; // reg ^ unmask delta
                }
            }
        }
        (regs, revealed)
    }

}

// =====================================================================
// EXAMPLE CIRCUIT:  F(a, b) = rotl( (a | b) ^ C , 5 )
//   a|b is built as (a ^ b) ^ (a & b) -> exercises the metered AND.
//   C is a SECRET_CONST -> exercises the obscured-constant path.
// =====================================================================
const C: u32 = 0x9e37_79b9;

// F(a, b) = rotl((a | b) ^ C, 5)
//   a|b expanded as (a^b)^(a&b) to exercise the metered AND.
pub fn build_example() -> Circuit {
    let mut b     = Builder::new();
    let wa        = b.ingest("a");
    let wb        = b.ingest("b");
    let wc        = b.secret_const(C);
    let a_xor_b   = b.xor(wa, wb);
    let a_and_b   = b.and(wa, wb);
    let a_or_b    = b.xor(a_xor_b, a_and_b);
    let xored     = b.xor(a_or_b, wc);
    let result    = b.rotl(xored, 5);
    b.build(result)
}

// F(a, b) = a + b (wrapping 32-bit addition) via the word-level ADD32.
pub fn build_add32_example() -> Circuit {
    let mut b  = Builder::new();
    let wa     = b.ingest("a");
    let wb     = b.ingest("b");
    let result = b.add32(wa, wb);
    b.build(result)
}

// reference (server) F, computed straight
fn ref_f(a: u32, b: u32) -> u32 {
    ((a | b) ^ C).rotate_left(5)
}

fn inputs_of(a: u32, b: u32) -> HashMap<String, u32> {
    let mut m = HashMap::new();
    m.insert("a".to_string(), a);
    m.insert("b".to_string(), b);
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use rand::{Rng, SeedableRng};
    use rand::rngs::StdRng;

    fn make_inputs(a: u32, b: u32) -> HashMap<String, u32> {
        HashMap::from([("a".to_string(), a), ("b".to_string(), b)])
    }

    // Independent reference so the test doesn't share code with the circuit builder.
    fn expected_f(a: u32, b: u32) -> u32 {
        ((a | b) ^ 0x9e3779b9_u32).rotate_left(5)
    }

    fn single_input(a: u32) -> HashMap<String, u32> {
        HashMap::from([("a".to_string(), a)])
    }

    // PublicConst: value is k and mask is always 0 (server can see it in plain).
    #[test]
    fn public_const_has_zero_mask() {
        let mut b = Builder::new();
        let k_wire = b.public_const(0x12345678);
        let c = b.build(k_wire);
        let mut rng = StdRng::seed_from_u64(0x1111);
        for _ in 0..20 {
            let seed: u64 = rng.random();
            let vm = ConcreteVm::from_circuit(&c, seed);
            assert_eq!(vm.masks[&k_wire], 0, "PublicConst mask should be 0 (seed={:#x})", seed);
            let (_, revealed) = vm.eval(&HashMap::new());
            assert_eq!(revealed, 0x12345678);
        }
    }

    // XorConst: F(a) = a ^ K.
    #[test]
    fn xor_const_computes_correctly() {
        const K: u32 = 0xdeadbeef;
        let mut b = Builder::new();
        let wa = b.ingest("a");
        let result = b.xor_const(wa, K);
        let c = b.build(result);
        let mut rng = StdRng::seed_from_u64(0x2222);
        for _ in 0..20 {
            let seed: u64 = rng.random();
            let vm = ConcreteVm::from_circuit(&c, seed);
            for _ in 0..20 {
                let a: u32 = rng.random();
                let (_, revealed) = vm.eval(&single_input(a));
                assert_eq!(revealed, a ^ K, "XorConst mismatch (seed={:#x})", seed);
            }
        }
    }

    // AndConst: F(a) = a & K.
    #[test]
    fn and_const_computes_correctly() {
        const K: u32 = 0x0f0f0f0f;
        let mut b = Builder::new();
        let wa = b.ingest("a");
        let result = b.and_const(wa, K);
        let c = b.build(result);
        let mut rng = StdRng::seed_from_u64(0x3333);
        for _ in 0..20 {
            let seed: u64 = rng.random();
            let vm = ConcreteVm::from_circuit(&c, seed);
            for _ in 0..20 {
                let a: u32 = rng.random();
                let (_, revealed) = vm.eval(&single_input(a));
                assert_eq!(revealed, a & K, "AndConst mismatch (seed={:#x})", seed);
            }
        }
    }

    // Remask: identity on values, rerandomises the mask.
    #[test]
    fn remask_preserves_value() {
        let mut b = Builder::new();
        let wa = b.ingest("a");
        let remasked = b.remask(wa);
        let c = b.build(remasked);
        let mut rng = StdRng::seed_from_u64(0x4444);
        for _ in 0..20 {
            let seed: u64 = rng.random();
            let vm = ConcreteVm::from_circuit(&c, seed);
            for _ in 0..20 {
                let a: u32 = rng.random();
                let inputs = single_input(a);
                let values = c.eval(&inputs);
                let (regs, revealed) = vm.eval(&inputs);
                // value identity
                assert_eq!(revealed, a, "Remask changed the value (seed={:#x})", seed);
                // register invariant on the remasked wire
                assert_eq!(
                    regs[&remasked],
                    values[&remasked] ^ vm.masks[&remasked],
                    "Remask wire reg != value^mask (seed={:#x})", seed,
                );
                // the mask did actually change (almost surely — p(collision) = 2^-32 per trial)
                assert_ne!(
                    vm.masks[&remasked], vm.masks[&wa],
                    "Remask left the mask unchanged (seed={:#x})", seed,
                );
            }
        }
    }

    // Structural: each AND gate owns a unique generator => triples never reused.
    #[test]
    fn no_triple_reuse() {
        let c = build_example();
        let and_gens: Vec<GenId> = c.gadgets.iter().filter_map(|g| {
            if let Gadget::And { gen, .. } = g { Some(*gen) } else { None }
        }).collect();
        let unique: HashSet<GenId> = and_gens.iter().copied().collect();
        assert_eq!(unique.len(), and_gens.len(), "AND gates share a generator");
    }

    // Egress must reveal exactly what the value graph and the independent reference compute.
    #[test]
    fn egress_matches_plaintext() {
        let c = build_example();
        let mut rng = StdRng::seed_from_u64(0xdead_beef);
        for _ in 0..200 {
            let seed: u64 = rng.random();
            let vm = ConcreteVm::from_circuit(&c, seed);
            for _ in 0..20 {
                let (a, b) = (rng.random(), rng.random());
                let inputs = make_inputs(a, b);
                let values = c.eval(&inputs);
                let (_, revealed) = vm.eval(&inputs);
                assert_eq!(values[&c.egress], expected_f(a, b), "value graph != ref_f");
                assert_eq!(revealed, expected_f(a, b), "egress mismatch (seed={:#x})", seed);
            }
        }
    }

    // Every non-egress register must hold value ^ mask.
    #[test]
    fn registers_hold_value_xor_mask() {
        let c = build_example();
        let mut rng = StdRng::seed_from_u64(0xdead_beef);
        for _ in 0..200 {
            let seed: u64 = rng.random();
            let vm = ConcreteVm::from_circuit(&c, seed);
            for _ in 0..20 {
                let (a, b) = (rng.random(), rng.random());
                let inputs = make_inputs(a, b);
                let values = c.eval(&inputs);
                let (regs, _) = vm.eval(&inputs);
                for (id, w) in c.wires.iter().enumerate() {
                    if *w == Wire::Egress { continue; }
                    assert_eq!(
                        regs[&id],
                        values[&id] ^ vm.masks[&id],
                        "wire {id}: reg != value^mask (seed={:#x})", seed,
                    );
                }
            }
        }
    }

    // ADD32 must compute wrapping 32-bit addition across all rotations.
    #[test]
    fn add32_matches_wrapping_add() {
        let c = build_add32_example();
        let mut rng = StdRng::seed_from_u64(0xcafe_babe);
        for _ in 0..20 {
            let seed: u64 = rng.random();
            let vm = ConcreteVm::from_circuit(&c, seed);
            for _ in 0..20 {
                let (a, b) = (rng.random::<u32>(), rng.random::<u32>());
                let inputs = make_inputs(a, b);
                let values = c.eval(&inputs);
                let (_, revealed) = vm.eval(&inputs);
                assert_eq!(values[&c.egress], a.wrapping_add(b), "value graph != wrapping_add");
                assert_eq!(revealed, a.wrapping_add(b), "ADD32 egress mismatch (seed={:#x})", seed);
            }
        }
    }

    // Structural: word-level optimization should cost exactly 31 triples.
    #[test]
    fn add32_uses_31_triples() {
        let c = build_add32_example();
        let count = c.gadgets.iter().filter(|g| matches!(g, Gadget::And { .. })).count();
        // 1 for G = A & B (all 32 generate bits) + 30 for carry propagate (bits 1–30)
        assert_eq!(count, 31, "ADD32 triple count");
    }

    // Every ingest wire must have a nonzero mask (non-degeneracy), and its
    // register must never equal the raw input value.
    #[test]
    fn ingest_wires_are_masked() {
        let c = build_example();
        let mut rng = StdRng::seed_from_u64(0xdead_beef);
        for _ in 0..200 {
            let seed: u64 = rng.random();
            let vm = ConcreteVm::from_circuit(&c, seed);
            // Masks are fixed per seed; check non-degeneracy before evaluating inputs.
            for g in &c.gadgets {
                if let Gadget::Ingest { name, out, .. } = g {
                    assert_ne!(
                        vm.masks[out], 0,
                        "ingest mask for '{}' is zero (seed={:#x})", name, seed,
                    );
                }
            }
            for _ in 0..20 {
                let (a, b) = (rng.random(), rng.random());
                let inputs = make_inputs(a, b);
                let (regs, _) = vm.eval(&inputs);
                for g in &c.gadgets {
                    if let Gadget::Ingest { name, out, .. } = g {
                        assert_ne!(
                            regs[out], inputs[name],
                            "input '{}' appeared raw (seed={:#x})", name, seed,
                        );
                    }
                }
            }
        }
    }
}

// =====================================================================
// DEMO: dump one concretization so you can see constants drop out.
// =====================================================================
pub fn demo() {
    let c = build_example();
    let a = 0x1234_5678u32;
    let b = 0x0bad_f00du32;

    for seed in [0x1111_1111u64, 0x2222_2222u64] {
        let vm = ConcreteVm::from_circuit(&c, seed);
        let (regs, revealed) = vm.eval(&inputs_of(a, b));

        println!("=== rotation seed={} ===", hx64(seed));
        let gens: Vec<String> = c
            .generators
            .iter()
            .enumerate()
            .map(|(id, g)| format!("g#{}={} ({})", id, hx32(vm.gen_values[&id]), g.purpose))
            .collect();
        println!("generators (the rotation key): {}", gens.join("  "));

        for (idx, g) in c.gadgets.iter().enumerate() {
            let bk = &vm.baked[idx];
            let (reg, mask) = match g.out() {
                Some(w) => (regs[&w], vm.masks[&w]),
                None => (revealed, 0),
            };
            let consts = if bk.consts.is_empty() {
                "consts={}".to_string()
            } else {
                format!(
                    "consts={{{}}}",
                    bk.consts.iter().map(|x| hx32(*x)).collect::<Vec<_>>().join(", ")
                )
            };
            println!(
                "  [{}] {:<12} reg={} mask={}  {}  // {}",
                idx,
                g.kind(),
                hx32(reg),
                hx32(mask),
                consts,
                bk.note
            );
        }
        println!(
            "  reveal={}  refF={}  {}\n",
            hx32(revealed),
            hx32(ref_f(a, b)),
            if revealed == ref_f(a, b) { "OK" } else { "FAIL" }
        );
    }
}
