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

use std::collections::HashMap;
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
    gadgets: Vec<Gadget>, // topological order
    wires: Vec<Wire>,     // indexed by WireId
    generators: Vec<Generator>,
    egress: WireId,
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
}

// ---------- what gets baked into a concrete VM image ----------
#[derive(Clone, Debug)]
pub struct BakedGadget {
    idx: usize,
    kind: &'static str,
    consts: Vec<u32>, // constant-pool entries this gadget references
    note: String,     // human-readable, for the demo dump
}

#[derive(Debug)]
pub struct ConcreteVm {
    circuit: Circuit,
    seed: u64,
    baked: Vec<BakedGadget>,
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
        let mut rng = StdRng::seed_from_u64(seed);

        // (4) sample every independent generator; GenId == index in c.generators
        let mut gen_values: HashMap<GenId, u32> = HashMap::new();
        for (id, _) in c.generators.iter().enumerate() {
            gen_values.insert(id, rng.random());
        }

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

pub fn build_example() -> Circuit {
    let wires = vec![
        Wire::Ingest,    // 0: a
        Wire::Ingest,    // 1: b
        Wire::Internal,  // 2: C (secret const)
        Wire::Internal,  // 3: a ^ b
        Wire::Internal,  // 4: a & b
        Wire::Internal,  // 5: a | b
        Wire::Internal,  // 6: (a|b) ^ C
        Wire::Egress,    // 7: rotl(.., 5)
    ];
    let gadgets = vec![
        Gadget::Ingest { name: "a".to_string(), gen: 0, out: 0 },
        Gadget::Ingest { name: "b".to_string(), gen: 1, out: 1 },
        Gadget::SecretConst { k: C, gen: 2, out: 2 },
        Gadget::Xor { a: 0, b: 1, out: 3 },         // a ^ b
        Gadget::And { a: 0, b: 1, gen: 3, out: 4 }, // a & b   (metered)
        Gadget::Xor { a: 3, b: 4, out: 5 },         // (a^b)^(a&b) = a|b
        Gadget::Xor { a: 5, b: 2, out: 6 },         // (a|b) ^ C
        Gadget::Rotl { a: 6, r: 5, out: 7 },        // rotl(.., 5)
        Gadget::Egress { a: 7 },
    ];
    let generators = vec![
        Generator { purpose: "ingest a" },
        Generator { purpose: "ingest b" },
        Generator { purpose: "secret const C" },
        Generator { purpose: "AND output mask" },
    ];
    Circuit { gadgets, wires, generators, egress: 7 }
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
