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
//!
//! After regenerating, remove the `#[ignore]` from the corresponding
//! correctness test in `tests/emit_tests.rs`.

use xorpl::{
    emit::emit_rust,
    fixture_defs::ALL_FIXTURES,
    lower::lower_to_circuit,
    vm::ConcreteVm,
};

fn main() {
    let mut wrote = 0usize;
    for def in ALL_FIXTURES {
        let circuit = lower_to_circuit(&def.expr());
        let vm = ConcreteVm::from_circuit(&circuit, def.seed);
        let source = emit_rust(&vm, def.name);

        let path = format!("tests/fixtures/{}.rs", def.name);
        std::fs::write(&path, &source)
            .unwrap_or_else(|e| panic!("failed to write {path}: {e}"));
        println!("wrote {path}");
        wrote += 1;
    }
    println!("{wrote} fixture(s) written — commit the updated files");
}
