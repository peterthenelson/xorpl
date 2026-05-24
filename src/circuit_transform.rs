//! Post-lowering circuit transforms.
//!
//! Each transform takes a `&Circuit` and returns a new `Circuit` with the same
//! functional semantics.  Transforms are applied after lowering and before
//! concretization; the result is what both the server mirrors and
//! `MaskedCircuit::from_circuit` consumes.
//!
//! # Implementation pattern
//!
//! Transforms replay the gadget list through a fresh `Builder`, maintaining a
//! `HashMap<WireId, WireId>` that maps old wire IDs to new ones.  This keeps
//! wire and generator allocation consistent and runs `Circuit::validate()`
//! automatically via `Builder::build`.

use std::collections::HashMap;

use rand::RngCore;

use crate::circuit::{Builder, Circuit, Gadget, WireId};

// ---------------------------------------------------------------------------
// inject_remasks
// ---------------------------------------------------------------------------

/// Probabilistically insert `Remask` gadgets after internal wire outputs.
///
/// Each AND output is always a remask candidate; other internal outputs are
/// included with probability `1/rate` (pass `rate = 4` for ~25%).  Source
/// gadgets (`Ingest`, `PublicConst`, `SecretConst`) are never remasked —
/// their masks are already independently fresh.
///
/// Downstream consumers of remasked wires transparently receive the remasked
/// wire through the remap table; no other change to circuit topology occurs.
pub fn inject_remasks(circuit: &Circuit, rng: &mut impl RngCore, rate: u32) -> Circuit {
    let mut builder = Builder::new();
    let mut remap: HashMap<WireId, WireId> = HashMap::new();

    for g in &circuit.gadgets {
        // Translate an old WireId through the remap table.
        let r = |id: WireId| remap[&id];

        let new_out: Option<WireId> = match g {
            // --- sources: emit as-is, record remap ---
            Gadget::Ingest { name, .. } => Some(builder.ingest(name)),
            Gadget::PublicConst { k, .. } => Some(builder.public_const(*k)),
            Gadget::SecretConst { k, .. } => Some(builder.secret_const(*k)),

            // --- linear ops ---
            Gadget::Xor { a, b, .. } => Some(builder.xor(r(*a), r(*b))),
            Gadget::XorConst { a, k, .. } => Some(builder.xor_const(r(*a), *k)),
            Gadget::AndConst { a, k, .. } => Some(builder.and_const(r(*a), *k)),
            Gadget::Rotl { a, r: rot, .. } => Some(builder.rotl(r(*a), *rot)),

            // --- nonlinear: AND outputs are prime remask candidates ---
            Gadget::And { a, b, .. } => {
                let w = builder.and(r(*a), r(*b));
                // Always eligible; apply with probability 1/rate.
                if should_remask(rng, rate) {
                    Some(builder.remask(w))
                } else {
                    Some(w)
                }
            }

            // --- existing Remask: re-emit (preserve existing structure) ---
            Gadget::Remask { a, .. } => Some(builder.remask(r(*a))),

            // --- egress: handled by builder.build() below ---
            Gadget::Egress { .. } => None,
        };

        // For non-Egress gadgets, also consider adding a Remask for linear outputs.
        let new_out = if let (Some(w), Some(old_out)) = (new_out, g.out()) {
            let w = match g {
                // AND outputs already handled above; sources are excluded.
                Gadget::And { .. }
                | Gadget::Ingest { .. }
                | Gadget::PublicConst { .. }
                | Gadget::SecretConst { .. }
                | Gadget::Remask { .. } => w,
                // Linear ops: apply remask with probability 1/rate.
                _ => {
                    if should_remask(rng, rate) {
                        builder.remask(w)
                    } else {
                        w
                    }
                }
            };
            remap.insert(old_out, w);
            Some(w)
        } else {
            None
        };

        let _ = new_out; // consumed via remap above
    }

    builder.build(remap[&circuit.egress])
}

fn should_remask(rng: &mut impl RngCore, rate: u32) -> bool {
    rng.next_u32() % rate == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    use crate::expr::Expr;
    use crate::lower::lower_to_circuit;
    use crate::mask::MaskedCircuit;

    fn verify_transform(circuit: &Circuit, transformed: &Circuit, inputs: &[(&str, u32)], expected: u32) {
        let input_map: HashMap<String, u32> = inputs.iter().map(|&(k, v)| (k.to_string(), v)).collect();

        let orig_vals = circuit.eval(&input_map);
        assert_eq!(orig_vals[&circuit.egress], expected, "original circuit wrong");

        let new_vals = transformed.eval(&input_map);
        assert_eq!(new_vals[&transformed.egress], expected, "transformed circuit wrong");

        for seed in 0u64..4 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let vm = MaskedCircuit::from_circuit(transformed, &mut rng);
            let (_regs, revealed) = vm.eval(transformed, &input_map);
            assert_eq!(revealed, expected, "concretized transformed circuit wrong (seed={seed})");
        }
    }

    #[test]
    fn inject_remasks_preserves_or_rotl() {
        let a = Expr::input("a");
        let b = Expr::input("b");
        let c = Expr::secret_const(0x9e37_79b9);
        let expr = Expr::rotl(Expr::xor(Expr::or(a, b), c), 5);
        let circuit = lower_to_circuit(&expr);

        let av: u32 = 0x1234_5678;
        let bv: u32 = 0xDEAD_BEEF;
        let expected = ((av | bv) ^ 0x9e37_79b9u32).rotate_left(5);

        for seed in 0u64..8 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let transformed = inject_remasks(&circuit, &mut rng, 3);
            verify_transform(&circuit, &transformed, &[("a", av), ("b", bv)], expected);
        }
    }

    #[test]
    fn inject_remasks_adds_remask_gadgets() {
        let a = Expr::input("a");
        let b = Expr::input("b");
        let expr = Expr::and(a, b);
        let circuit = lower_to_circuit(&expr);

        // With rate=1 every eligible wire gets remasked — there must be more gadgets.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let transformed = inject_remasks(&circuit, &mut rng, 1);
        let remask_count = transformed.gadgets.iter()
            .filter(|g| matches!(g, Gadget::Remask { .. }))
            .count();
        assert!(remask_count > 0, "expected Remask gadgets with rate=1");
    }

    #[test]
    fn inject_remasks_chacha_qr() {
        let a = Expr::input("a");
        let b = Expr::input("b");
        let c = Expr::input("c");
        let d = Expr::input("d");
        let a1 = Expr::add(a.clone(),  b.clone());
        let d2 = Expr::rotl(Expr::xor(d.clone(),  a1.clone()), 16);
        let c1 = Expr::add(c.clone(),  d2.clone());
        let b2 = Expr::rotl(Expr::xor(b.clone(),  c1.clone()), 12);
        let a2 = Expr::add(a1,         b2.clone());
        let d4 = Expr::rotl(Expr::xor(d2,         a2.clone()),  8);
        let c2 = Expr::add(c1,         d4.clone());
        let b4 = Expr::rotl(Expr::xor(b2,         c2.clone()),  7);
        let expr = Expr::xor(Expr::xor(a2, b4), Expr::xor(c2, d4));

        let av: u32 = 0x11111111;
        let bv: u32 = 0x22222222;
        let cv: u32 = 0x33333333;
        let dv: u32 = 0x44444444;

        let circuit = lower_to_circuit(&expr);
        let orig_vals = circuit.eval(
            &[("a", av), ("b", bv), ("c", cv), ("d", dv)]
                .iter().map(|&(k, v)| (k.to_string(), v)).collect()
        );
        let expected = orig_vals[&circuit.egress];

        for seed in 0u64..4 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let transformed = inject_remasks(&circuit, &mut rng, 4);
            verify_transform(&circuit, &transformed,
                &[("a", av), ("b", bv), ("c", cv), ("d", dv)], expected);
        }
    }
}
