//! Integration tests for the emit pipeline.
//!
//! Test categories:
//!
//! - **Correctness** (`*::gives_right_answer`): include the committed fixture
//!   source and call the emitted function on known inputs.  Marked `#[ignore]`
//!   until the fixture file is populated — run `cargo run --bin regen_fixtures`
//!   and then remove the `#[ignore]`.
//!
//! - **Skew check** (`fixtures_not_out_of_sync`): re-emit every fixture and
//!   assert the output matches the file on disk.  Catches regenerating the
//!   emitter without regenerating the fixtures.
//!
//! - **Structural** (`structural_properties`): check properties of the emitted
//!   string (function signature, POOL constant, param names) without needing
//!   to compile the output.
//!
//! The skew check and structural tests iterate over `ALL_FIXTURES` and pick up
//! new fixtures automatically.  When adding a new fixture, add one correctness
//! test block below and follow the instructions in `src/fixture_defs.rs`.

use xorpl::{
    emit::emit_rust,
    fixture_defs::ALL_FIXTURES,
    lower::lower_to_circuit,
    vm::ConcreteVm,
};

// ---------------------------------------------------------------------------
// Correctness tests
//
// One module per fixture.  When adding a new fixture:
//   1. Add a `mod <name> { include!(...); #[test] ... }` block here.
//   2. Remove #[ignore] after running `cargo run --bin regen_fixtures`.
// ---------------------------------------------------------------------------

mod or_rotl_demo {
    include!("fixtures/or_rotl_demo.rs");

    #[test]
    fn gives_right_answer() {
        let cases: &[(u32, u32)] = &[
            (0x0000_0000, 0x0000_0000),
            (0xFFFF_FFFF, 0xFFFF_FFFF),
            (0x1234_5678, 0xDEAD_BEEF),
            (0xAAAA_AAAA, 0x5555_5555),
        ];
        for &(a, b) in cases {
            let expected = ((a | b) ^ 0x9e37_79b9u32).rotate_left(5);
            assert_eq!(or_rotl_demo(a, b), expected, "inputs ({a:#010x}, {b:#010x})");
        }
    }
}

// ---------------------------------------------------------------------------
// Skew check (automatic — driven by ALL_FIXTURES)
// ---------------------------------------------------------------------------

#[test]
fn fixtures_not_out_of_sync() {
    for def in ALL_FIXTURES {
        let circuit = lower_to_circuit(&(def.build)());
        let vm = ConcreteVm::from_circuit(&circuit, def.seed);
        let emitted = emit_rust(&vm, def.name, def.param_names);

        let path = format!("tests/fixtures/{}.rs", def.name);
        let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("cannot read {path}: {e}\nRun `cargo run --bin regen_fixtures`")
        });

        assert_eq!(
            emitted, on_disk,
            "fixture `{}.rs` is out of sync — run `cargo run --bin regen_fixtures`",
            def.name
        );
    }
}

// ---------------------------------------------------------------------------
// Structural tests (automatic — driven by ALL_FIXTURES)
// ---------------------------------------------------------------------------

#[test]
fn structural_properties() {
    for def in ALL_FIXTURES {
        let circuit = lower_to_circuit(&(def.build)());
        let vm = ConcreteVm::from_circuit(&circuit, def.seed);
        let emitted = emit_rust(&vm, def.name, def.param_names);

        assert!(
            emitted.contains("const POOL"),
            "[{}] emitted source is missing `const POOL`",
            def.name
        );
        assert!(
            emitted.contains(&format!("pub fn {}(", def.name)),
            "[{}] emitted source has wrong or missing function name",
            def.name
        );
        assert!(
            emitted.contains("-> u32"),
            "[{}] emitted source has wrong return type",
            def.name
        );
        for p in def.param_names {
            assert!(
                emitted.contains(p),
                "[{}] param `{p}` missing from emitted signature",
                def.name
            );
        }
    }
}
