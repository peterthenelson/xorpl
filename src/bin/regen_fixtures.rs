//! Regenerate all committed emit fixtures.
//!
//! Run with:
//!
//! ```text
//! cargo run --bin regen_fixtures
//! ```
//!
//! This overwrites every `tests/fixtures/<name>.rs` listed in
//! `xorpl::fixture_defs::ALL_FIXTURES`.  Run it after changing the emitter
//! or after adding a new fixture definition.  Commit the updated files
//! alongside any emitter changes.

use rand::SeedableRng;
use rand::rngs::StdRng;

use xorpl::{
    emit::{emit_rust, emit_verifier_rust},
    expr::expr_digest,
    fixture_defs::ALL_FIXTURES,
    lower::lower_to_circuit,
    mask::MaskedCircuit,
};

fn main() {
    let mut wrote = 0usize;

    for def in ALL_FIXTURES {
        // The digest and verifier are always derived from the original
        // (pre-strong_rotate) expression so they are stable across rotations.
        let original = (def.build)();
        let digest   = expr_digest(&original, None);

        // Browser (obfuscated) fixture: use def.expr() which applies
        // strong_rotate when structure_seed is set.
        let circuit = lower_to_circuit(&def.expr());
        let mut rng = StdRng::seed_from_u64(def.seed);
        let masked  = MaskedCircuit::from_circuit(&circuit, &mut rng);
        let source  = emit_rust(&masked, &circuit, def.name, &mut rng, &digest);
        let path = format!("tests/fixtures/{}.rs", def.name);
        std::fs::write(&path, &source)
            .unwrap_or_else(|e| panic!("failed to write {path}: {e}"));
        println!("wrote {path}");
        wrote += 1;

        // Verifier fixture: lower the original (canonical) expression.
        let canonical    = lower_to_circuit(&original);
        let verify_name  = format!("{}_verify", def.name);
        let verifier     = emit_verifier_rust(&canonical, &verify_name, &digest);
        let verify_path  = format!("tests/fixtures/{}_verify.rs", def.name);
        std::fs::write(&verify_path, &verifier)
            .unwrap_or_else(|e| panic!("failed to write {verify_path}: {e}"));
        println!("wrote {verify_path}");
        wrote += 1;
    }

    println!("{wrote} fixture(s) written — commit the updated files");
}
