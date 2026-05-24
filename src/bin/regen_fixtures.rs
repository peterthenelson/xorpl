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
    emit::emit_rust,
    fixture_defs::ALL_FIXTURES,
    lower::lower_to_circuit,
    mask::MaskedCircuit,
};

fn main() {
    let mut wrote = 0usize;
    for def in ALL_FIXTURES {
        let circuit = lower_to_circuit(&def.expr());
        let mut rng = StdRng::seed_from_u64(def.seed);
        let masked  = MaskedCircuit::from_circuit(&circuit, &mut rng);
        let source  = emit_rust(&masked, &circuit, def.name, &mut rng);

        let path = format!("tests/fixtures/{}.rs", def.name);
        std::fs::write(&path, &source)
            .unwrap_or_else(|e| panic!("failed to write {path}: {e}"));
        println!("wrote {path}");
        wrote += 1;
    }
    println!("{wrote} fixture(s) written — commit the updated files");
}
