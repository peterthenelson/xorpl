//! Integration tests for the emit pipeline.
//!
//! Test categories:
//!
//! - **Correctness** (`*::gives_right_answer`): include the committed fixture
//!   source and call the emitted function on known inputs.
//!
//! - **Skew check** (`fixtures_not_out_of_sync`): re-emit every fixture and
//!   assert the output matches the file on disk.  Catches changing the emitter
//!   without regenerating the fixtures.
//!
//! - **Structural** (`structural_properties`): check properties of the emitted
//!   string (function signature, POOL constant) without needing to compile it.
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
//   1. Add a placeholder file at tests/fixtures/<name>.rs
//   2. Add a `mod <name> { include!(...); #[test] fn gives_right_answer() { ... } }` block here.
//   3. Run `cargo run --bin regen_fixtures` then remove any #[ignore].
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

mod add32_demo {
    include!("fixtures/add32_demo.rs");

    #[test]
    fn gives_right_answer() {
        let cases: &[(u32, u32)] = &[
            (0, 0),
            (1, 1),
            (0xFFFF_FFFF, 1),           // wrapping overflow
            (0x1234_5678, 0x8765_4321),
            (0xDEAD_BEEF, 0xCAFE_BABE),
        ];
        for &(a, b) in cases {
            let expected = a.wrapping_add(b);
            assert_eq!(add32_demo(a, b), expected, "inputs ({a:#010x}, {b:#010x})");
        }
    }
}

mod mux_demo {
    include!("fixtures/mux_demo.rs");

    #[test]
    fn gives_right_answer() {
        // All-ones selects t
        assert_eq!(mux_demo(0xFFFF_FFFF, 0xAAAA_AAAA, 0x5555_5555), 0xAAAA_AAAA);
        // All-zeros selects f
        assert_eq!(mux_demo(0x0000_0000, 0xAAAA_AAAA, 0x5555_5555), 0x5555_5555);
        // Mixed cond: bitwise select
        assert_eq!(mux_demo(0xFFFF_0000, 0xDEAD_BEEF, 0xCAFE_BABE), 0xDEAD_BABE);
        assert_eq!(mux_demo(0x0000_FFFF, 0xDEAD_BEEF, 0xCAFE_BABE), 0xCAFE_BEEF);
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
        let emitted = emit_rust(&vm, def.name);

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
        let emitted = emit_rust(&vm, def.name);

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
    }
}
