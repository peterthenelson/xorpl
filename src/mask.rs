//! Concretization: `Circuit` → `MaskedCircuit`.
//!
//! Takes a salt-free `Circuit` and a seeded RNG and produces a `MaskedCircuit`
//! — a baked schedule of gadgets with concrete XOR masks, Beaver triples, and
//! secret-constant deltas committed to specific values.
//!
//! The caller (pipeline or fixture) owns all seeds and RNG state.
//! `MaskedCircuit` stores only the derived artefacts, not the seed.

use std::collections::HashMap;

use rand::{Rng, RngCore, SeedableRng};
use rand::rngs::StdRng;

use crate::circuit::{Circuit, Gadget, GenId, WireId};

// ---------------------------------------------------------------------------
// MaskedGadget
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct MaskedGadget {
    #[allow(dead_code)] idx:  usize,
    #[allow(dead_code)] kind: &'static str,
    consts: Vec<u32>,
    note:   String,
}

// ---------------------------------------------------------------------------
// MaskedCircuit
// ---------------------------------------------------------------------------

/// A `Circuit` concretized with XOR masks, Beaver triples, and baked
/// constants.  This is the client artifact — pass it to `emit_rust` to get
/// deployable Rust source.
#[derive(Debug)]
pub struct MaskedCircuit {
    baked:      Vec<MaskedGadget>,
    pub(crate) masks:      HashMap<WireId, u32>, // debug / sanity — not shipped
    gen_values: HashMap<GenId, u32>,             // the rotation key
}

impl MaskedCircuit {
    // =========================================================================
    // Accessors for emit
    // =========================================================================

    /// Iterator over each gadget's constant-pool slice, in gadget order.
    pub(crate) fn baked_consts(&self) -> impl Iterator<Item = &[u32]> {
        self.baked.iter().map(|mg| mg.consts.as_slice())
    }

    // =========================================================================
    // Concretization
    // =========================================================================

    /// Concretize `circuit` using randomness from `rng`.
    ///
    /// Samples a fresh mask for every generator, retrying until all
    /// secret-carrying masks (Ingest, SecretConst) are non-zero.  Then
    /// propagates masks through the gadget schedule and bakes constants.
    pub fn from_circuit(circuit: &Circuit, rng: &mut impl RngCore) -> MaskedCircuit {
        circuit.validate().expect("invalid circuit");

        let secret_gens: Vec<GenId> = circuit.gadgets.iter()
            .filter_map(|g| match g {
                Gadget::Ingest { gen, .. } | Gadget::SecretConst { gen, .. } => Some(*gen),
                _ => None,
            })
            .collect();

        // Sample generators, retrying until no secret mask is zero.
        let gen_values: HashMap<GenId, u32> = loop {
            let mut gv: HashMap<GenId, u32> = HashMap::new();
            for (id, _) in circuit.generators.iter().enumerate() {
                gv.insert(id, rng.random());
            }
            if secret_gens.iter().all(|g| gv[g] != 0) {
                break gv;
            }
        };

        let mut masks: HashMap<WireId, u32> = HashMap::new();
        let mut baked: Vec<MaskedGadget>    = Vec::new();

        for (idx, g) in circuit.gadgets.iter().enumerate() {
            let kind = g.kind();
            let (consts, note): (Vec<u32>, String) = match g {
                Gadget::PublicConst { k, out } => {
                    masks.insert(*out, 0);
                    (vec![*k], format!("public {}", hx32(*k)))
                }
                Gadget::SecretConst { k, gen, out } => {
                    let m = gen_values[gen];
                    masks.insert(*out, m);
                    (vec![*k ^ m], format!("bake k^mask (mask=gen#{})", gen))
                }
                Gadget::Ingest { name, gen, out } => {
                    let m = gen_values[gen];
                    masks.insert(*out, m);
                    (vec![m], format!("XOR \"{}\" with ingest mask gen#{}", name, gen))
                }
                Gadget::Xor { a, b, out } => {
                    masks.insert(*out, masks[a] ^ masks[b]);
                    (vec![], "free".to_string())
                }
                Gadget::XorConst { a, k, out } => {
                    masks.insert(*out, masks[a]);
                    (vec![*k], "free; mask unchanged".to_string())
                }
                Gadget::AndConst { a, k, out } => {
                    masks.insert(*out, masks[a] & *k);
                    (vec![*k], "free; mask &= k".to_string())
                }
                Gadget::Rotl { a, r, out } => {
                    masks.insert(*out, masks[a].rotate_left(*r));
                    (vec![], "free; mask rotated".to_string())
                }
                Gadget::And { a, b, gen, out } => {
                    let (ma, mb, mz) = (masks[a], masks[b], gen_values[gen]);
                    masks.insert(*out, mz);
                    let t = (ma & mb) ^ mz;
                    (vec![t, ma, mb], format!("triple [T, ma, mb], out mask=gen#{}", gen))
                }
                Gadget::Remask { a, gen, out } => {
                    let target = gen_values[gen];
                    let delta  = masks[a] ^ target;
                    masks.insert(*out, target);
                    (vec![delta], format!("XOR remask delta -> gen#{}", gen))
                }
                Gadget::Egress { a } => {
                    (vec![masks[a]], "unmask & reveal".to_string())
                }
            };
            baked.push(MaskedGadget { idx, kind, consts, note });
        }

        MaskedCircuit { baked, masks, gen_values }
    }

    // =========================================================================
    // Masked evaluation (proves the scheme closes)
    // =========================================================================

    /// Run the masked computation.  Returns `(registers, revealed)` where
    /// every register holds `value ^ mask` and `revealed` is the plaintext
    /// output.
    pub(crate) fn eval(
        &self,
        circuit: &Circuit,
        inputs:  &HashMap<String, u32>,
    ) -> (HashMap<WireId, u32>, u32) {
        let mut regs: HashMap<WireId, u32> = HashMap::new();
        let mut revealed: u32 = 0;

        for (idx, g) in circuit.gadgets.iter().enumerate() {
            let k = &self.baked[idx].consts;
            match g {
                Gadget::PublicConst { out, .. }  => { regs.insert(*out, k[0]); }
                Gadget::SecretConst { out, .. }  => { regs.insert(*out, k[0]); }
                Gadget::Ingest { name, out, .. } => { regs.insert(*out, inputs[name] ^ k[0]); }
                Gadget::Xor { a, b, out }        => { regs.insert(*out, regs[a] ^ regs[b]); }
                Gadget::XorConst { a, out, .. }  => { regs.insert(*out, regs[a] ^ k[0]); }
                Gadget::AndConst { a, out, .. }  => { regs.insert(*out, regs[a] & k[0]); }
                Gadget::Rotl { a, r, out }       => { regs.insert(*out, regs[a].rotate_left(*r)); }
                Gadget::And { a, b, out, .. } => {
                    let (t, ma, mb) = (k[0], k[1], k[2]);
                    let (ra, rb) = (regs[a], regs[b]);
                    let mut z = t;
                    z ^= ra & mb;
                    z ^= rb & ma;
                    z ^= ra & rb;
                    regs.insert(*out, z);
                }
                Gadget::Remask { a, out, .. } => { regs.insert(*out, regs[a] ^ k[0]); }
                Gadget::Egress { a }          => { revealed = regs[a] ^ k[0]; }
            }
        }
        (regs, revealed)
    }
}

// ---------------------------------------------------------------------------
// Helpers (used by mask tests and demo)
// ---------------------------------------------------------------------------

fn hx32(x: u32) -> String { format!("0x{x:08x}") }
fn hx64(x: u64) -> String { format!("0x{x:016x}") }

fn inputs_of(a: u32, b: u32) -> HashMap<String, u32> {
    [("a".to_string(), a), ("b".to_string(), b)].into()
}

// ---------------------------------------------------------------------------
// Demo dump
// ---------------------------------------------------------------------------

/// Print a human-readable concretization dump for the example circuit
/// `F(a,b) = rotl((a|b)^C, 5)`.  Called from `src/bin/demo.rs`.
pub fn demo() {
    let c = crate::circuit::build_example();
    let a = 0x1234_5678u32;
    let b = 0x0bad_f00du32;
    let ref_out = |a: u32, b: u32| ((a | b) ^ 0x9e37_79b9u32).rotate_left(5);

    for seed in [0x1111_1111u64, 0x2222_2222u64] {
        let mut rng = StdRng::seed_from_u64(seed);
        let vm  = MaskedCircuit::from_circuit(&c, &mut rng);
        let (regs, revealed) = vm.eval(&c, &inputs_of(a, b));

        println!("=== rotation seed={} ===", hx64(seed));
        let gens: Vec<String> = c.generators.iter().enumerate()
            .map(|(id, g)| format!("g#{}={} ({})", id, hx32(vm.gen_values[&id]), g.purpose))
            .collect();
        println!("generators (the rotation key): {}", gens.join("  "));

        for (idx, g) in c.gadgets.iter().enumerate() {
            let bk = &vm.baked[idx];
            let (reg, mask) = match g.out() {
                Some(w) => (regs[&w], vm.masks[&w]),
                None    => (revealed, 0),
            };
            let consts = if bk.consts.is_empty() {
                "consts={}".to_string()
            } else {
                format!("consts={{{}}}", bk.consts.iter().map(|x| hx32(*x)).collect::<Vec<_>>().join(", "))
            };
            println!(
                "  [{}] {:<12} reg={} mask={}  {}  // {}",
                idx, g.kind(), hx32(reg), hx32(mask), consts, bk.note
            );
        }
        println!(
            "  reveal={}  refF={}  {}\n",
            hx32(revealed), hx32(ref_out(a, b)),
            if revealed == ref_out(a, b) { "OK" } else { "FAIL" }
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use crate::circuit::{build_add32_example, build_example, Builder, Gadget, Wire};

    fn single_input(a: u32) -> HashMap<String, u32> {
        [("a".to_string(), a)].into()
    }

    fn rng(seed: u64) -> StdRng { StdRng::seed_from_u64(seed) }

    #[test]
    fn public_const_has_zero_mask() {
        let mut b = Builder::new();
        let k_wire = b.public_const(0x12345678);
        let c = b.build(k_wire);
        let mut outer = rng(0x1111);
        for _ in 0..20 {
            let seed: u64 = outer.random();
            let vm = MaskedCircuit::from_circuit(&c, &mut rng(seed));
            assert_eq!(vm.masks[&k_wire], 0, "seed={seed:#x}");
            let (_, revealed) = vm.eval(&c, &HashMap::new());
            assert_eq!(revealed, 0x12345678);
        }
    }

    #[test]
    fn xor_const_computes_correctly() {
        const K: u32 = 0xdeadbeef;
        let mut b = Builder::new();
        let wa = b.ingest("a");
        let result = b.xor_const(wa, K);
        let c = b.build(result);
        let mut outer = rng(0x2222);
        for _ in 0..20 {
            let seed: u64 = outer.random();
            let vm = MaskedCircuit::from_circuit(&c, &mut rng(seed));
            for _ in 0..20 {
                let a: u32 = outer.random();
                let (_, revealed) = vm.eval(&c, &single_input(a));
                assert_eq!(revealed, a ^ K, "seed={seed:#x}");
            }
        }
    }

    #[test]
    fn and_const_computes_correctly() {
        const K: u32 = 0x0f0f0f0f;
        let mut b = Builder::new();
        let wa = b.ingest("a");
        let result = b.and_const(wa, K);
        let c = b.build(result);
        let mut outer = rng(0x3333);
        for _ in 0..20 {
            let seed: u64 = outer.random();
            let vm = MaskedCircuit::from_circuit(&c, &mut rng(seed));
            for _ in 0..20 {
                let a: u32 = outer.random();
                let (_, revealed) = vm.eval(&c, &single_input(a));
                assert_eq!(revealed, a & K, "seed={seed:#x}");
            }
        }
    }

    #[test]
    fn remask_preserves_value() {
        let mut b = Builder::new();
        let wa       = b.ingest("a");
        let remasked = b.remask(wa);
        let c = b.build(remasked);
        let mut outer = rng(0x4444);
        for _ in 0..20 {
            let seed: u64 = outer.random();
            let vm = MaskedCircuit::from_circuit(&c, &mut rng(seed));
            for _ in 0..20 {
                let a: u32 = outer.random();
                let inputs = single_input(a);
                let values = c.eval(&inputs);
                let (regs, revealed) = vm.eval(&c, &inputs);
                assert_eq!(revealed, a, "seed={seed:#x}");
                assert_eq!(regs[&remasked], values[&remasked] ^ vm.masks[&remasked], "seed={seed:#x}");
                assert_ne!(vm.masks[&remasked], vm.masks[&wa], "seed={seed:#x}");
            }
        }
    }

    #[test]
    fn egress_matches_plaintext() {
        let c = build_example();
        let expected = |a: u32, b: u32| ((a | b) ^ 0x9e3779b9_u32).rotate_left(5);
        let mut outer = rng(0xdead_beef);
        for _ in 0..200 {
            let seed: u64 = outer.random();
            let vm = MaskedCircuit::from_circuit(&c, &mut rng(seed));
            for _ in 0..20 {
                let (a, b): (u32, u32) = (outer.random(), outer.random());
                let inputs = inputs_of(a, b);
                let values = c.eval(&inputs);
                let (_, revealed) = vm.eval(&c, &inputs);
                assert_eq!(values[&c.egress], expected(a, b), "value graph != ref");
                assert_eq!(revealed, expected(a, b), "seed={seed:#x}");
            }
        }
    }

    #[test]
    fn registers_hold_value_xor_mask() {
        let c = build_example();
        let mut outer = rng(0xdead_beef);
        for _ in 0..200 {
            let seed: u64 = outer.random();
            let vm = MaskedCircuit::from_circuit(&c, &mut rng(seed));
            for _ in 0..20 {
                let (a, b): (u32, u32) = (outer.random(), outer.random());
                let inputs = inputs_of(a, b);
                let values = c.eval(&inputs);
                let (regs, _) = vm.eval(&c, &inputs);
                for (id, w) in c.wires.iter().enumerate() {
                    if *w == Wire::Egress { continue; }
                    assert_eq!(regs[&id], values[&id] ^ vm.masks[&id], "wire {id} seed={seed:#x}");
                }
            }
        }
    }

    #[test]
    fn add32_matches_wrapping_add() {
        let c = build_add32_example();
        let mut outer = rng(0xcafe_babe);
        for _ in 0..20 {
            let seed: u64 = outer.random();
            let vm = MaskedCircuit::from_circuit(&c, &mut rng(seed));
            for _ in 0..20 {
                let (a, b): (u32, u32) = (outer.random(), outer.random());
                let inputs = inputs_of(a, b);
                let values = c.eval(&inputs);
                let (_, revealed) = vm.eval(&c, &inputs);
                assert_eq!(values[&c.egress], a.wrapping_add(b), "value graph");
                assert_eq!(revealed, a.wrapping_add(b), "seed={seed:#x}");
            }
        }
    }

    #[test]
    fn ingest_wires_are_masked() {
        let c = build_example();
        let mut outer = rng(0xdead_beef);
        for _ in 0..200 {
            let seed: u64 = outer.random();
            let vm = MaskedCircuit::from_circuit(&c, &mut rng(seed));
            for g in &c.gadgets {
                if let Gadget::Ingest { name, out, .. } = g {
                    assert_ne!(vm.masks[out], 0, "ingest '{}' zero mask seed={seed:#x}", name);
                }
            }
            for _ in 0..20 {
                let (a, b): (u32, u32) = (outer.random(), outer.random());
                let inputs = inputs_of(a, b);
                let (regs, _) = vm.eval(&c, &inputs);
                for g in &c.gadgets {
                    if let Gadget::Ingest { name, out, .. } = g {
                        assert_ne!(regs[out], inputs[name], "input '{}' raw seed={seed:#x}", name);
                    }
                }
            }
        }
    }
}
