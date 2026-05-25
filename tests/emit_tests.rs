#![allow(dead_code)] // ROTATION_TAG in fixture includes is used by the skew check, not the correctness modules
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

use rand::SeedableRng;
use rand::rngs::StdRng;

use xorpl::prelude::*;
use xorpl::fixture_defs::ALL_FIXTURES;

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
            (0xFFFF_FFFF, 1),
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
        assert_eq!(mux_demo(0xFFFF_FFFF, 0xAAAA_AAAA, 0x5555_5555), 0xAAAA_AAAA);
        assert_eq!(mux_demo(0x0000_0000, 0xAAAA_AAAA, 0x5555_5555), 0x5555_5555);
        assert_eq!(mux_demo(0xFFFF_0000, 0xDEAD_BEEF, 0xCAFE_BABE), 0xDEAD_BABE);
        assert_eq!(mux_demo(0x0000_FFFF, 0xDEAD_BEEF, 0xCAFE_BABE), 0xCAFE_BEEF);
    }
}

mod or_rotl_mux_decoy {
    include!("fixtures/or_rotl_mux_decoy.rs");

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
            assert_eq!(or_rotl_mux_decoy(a, b), expected, "inputs ({a:#010x}, {b:#010x})");
        }
    }
}

fn chacha_qr_expected(a: u32, b: u32, c: u32, d: u32) -> u32 {
    let a1 = a.wrapping_add(b);
    let d2 = (d ^ a1).rotate_left(16);
    let c1 = c.wrapping_add(d2);
    let b2 = (b ^ c1).rotate_left(12);
    let a2 = a1.wrapping_add(b2);
    let d4 = (d2 ^ a2).rotate_left(8);
    let c2 = c1.wrapping_add(d4);
    let b4 = (b2 ^ c2).rotate_left(7);
    a2 ^ b4 ^ c2 ^ d4
}

fn qr_outputs(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let a1 = a.wrapping_add(b);
    let d2 = (d ^ a1).rotate_left(16);
    let c1 = c.wrapping_add(d2);
    let b2 = (b ^ c1).rotate_left(12);
    let a2 = a1.wrapping_add(b2);
    let d4 = (d2 ^ a2).rotate_left(8);
    let c2 = c1.wrapping_add(d4);
    let b4 = (b2 ^ c2).rotate_left(7);
    (a2, b4, c2, d4)
}

fn sha256_qr_expected(w: [u32; 8]) -> u32 {
    let (a, b, c, d) = qr_outputs(w[0], w[1], w[2], w[3]);
    let (e, f, g, h) = qr_outputs(w[4], w[5], w[6], w[7]);
    let (r0, r1, r2, r3) = qr_outputs(a ^ e, b ^ f, c ^ g, d ^ h);
    r0 ^ r1 ^ r2 ^ r3
}

mod chacha_qr {
    use super::chacha_qr_expected as expected;
    include!("fixtures/chacha_qr.rs");

    #[test]
    fn gives_right_answer() {
        let cases: &[(u32, u32, u32, u32)] = &[
            (0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000),
            (0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF),
            (0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574),
            (0xDEAD_BEEF, 0xCAFE_BABE, 0x1234_5678, 0x8765_4321),
        ];
        for &(a, b, c, d) in cases {
            assert_eq!(chacha_qr(a, b, c, d), expected(a, b, c, d),
                "inputs ({a:#010x}, {b:#010x}, {c:#010x}, {d:#010x})");
        }
    }
}

mod chacha_qr_rotated {
    use super::chacha_qr_expected as expected;
    include!("fixtures/chacha_qr_rotated.rs");

    #[test]
    fn gives_right_answer() {
        let cases: &[(u32, u32, u32, u32)] = &[
            (0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000),
            (0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF),
            (0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574),
            (0xDEAD_BEEF, 0xCAFE_BABE, 0x1234_5678, 0x8765_4321),
        ];
        for &(a, b, c, d) in cases {
            assert_eq!(chacha_qr_rotated(a, b, c, d), expected(a, b, c, d),
                "inputs ({a:#010x}, {b:#010x}, {c:#010x}, {d:#010x})");
        }
    }
}

mod sha256_qr {
    use super::sha256_qr_expected as expected;
    include!("fixtures/sha256_qr.rs");

    #[test]
    fn gives_right_answer() {
        let cases: &[[u32; 8]] = &[
            [0x0000_0000; 8],
            [0xFFFF_FFFF; 8],
            [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574,
             0xDEAD_BEEF, 0xCAFE_BABE, 0x1234_5678, 0x8765_4321],
        ];
        for &w in cases {
            assert_eq!(
                sha256_qr(w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]),
                expected(w),
                "inputs {w:08x?}",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Skew check
// ---------------------------------------------------------------------------

#[test]
fn fixtures_not_out_of_sync() {
    for def in ALL_FIXTURES {
        let circuit = lower_to_circuit(&def.expr());
        let mut rng = StdRng::seed_from_u64(def.seed);
        let masked  = MaskedCircuit::from_circuit(&circuit, &mut rng);
        let emitted = emit_rust(&masked, &circuit, def.name, &mut rng);

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
// Verifier correctness
// ---------------------------------------------------------------------------

mod or_rotl_demo_verifier {
    include!("fixtures/or_rotl_demo_verifier.rs");

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
            assert_eq!(or_rotl_demo_verify(a, b), expected,
                "inputs ({a:#010x}, {b:#010x})");
        }
    }
}

// ---------------------------------------------------------------------------
// Verifier skew check
// ---------------------------------------------------------------------------

#[test]
fn verifier_fixture_not_out_of_sync() {
    let a = Expr::input("a");
    let b = Expr::input("b");
    let c = Expr::secret_const(0x9e37_79b9);
    let expr = Expr::rotl(Expr::xor(Expr::or(a, b), c), 5);
    let circuit = lower_to_circuit(&expr);
    let emitted = emit_verifier_rust(&circuit, "or_rotl_demo_verify");

    let path    = "tests/fixtures/or_rotl_demo_verifier.rs";
    let on_disk = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));

    assert_eq!(emitted, on_disk,
        "verifier fixture is out of sync — re-emit with emit_verifier_rust");
}

// ---------------------------------------------------------------------------
// Verifier parameter naming
// ---------------------------------------------------------------------------

/// Parameters use the `input_{name}` prefix so they can never collide with the
/// `w{wire_id}` intermediates, even when circuit inputs are named "w0".."w7".
#[test]
fn verifier_parameters_use_input_prefix() {
    // Use input names that match the wire-id namespace — the pattern that
    // previously caused shadowing before the `input_` prefix was introduced.
    let circuit = lower_to_circuit(&Expr::xor(Expr::input("w0"), Expr::input("w7")));
    let verifier = emit_verifier_rust(&circuit, "verify");
    assert!(verifier.contains("input_w0: u32"), "expected input_w0 parameter:\n{verifier}");
    assert!(verifier.contains("input_w7: u32"), "expected input_w7 parameter:\n{verifier}");
    assert!(verifier.contains("let w0 = input_w0;"), "expected ingest binding:\n{verifier}");
    assert!(verifier.contains("let w1 = input_w7;"), "expected ingest binding:\n{verifier}");
}

// ---------------------------------------------------------------------------
// Structural tests
// ---------------------------------------------------------------------------

#[test]
fn structural_properties() {
    for def in ALL_FIXTURES {
        let circuit = lower_to_circuit(&def.expr());
        let mut rng = StdRng::seed_from_u64(def.seed);
        let masked  = MaskedCircuit::from_circuit(&circuit, &mut rng);
        let emitted = emit_rust(&masked, &circuit, def.name, &mut rng);

        assert!(emitted.contains("pub const ROTATION_TAG"),
            "[{}] missing `pub const ROTATION_TAG`", def.name);
        assert!(emitted.contains("const POOL"),
            "[{}] missing `const POOL`", def.name);
        assert!(emitted.contains(&format!("pub fn {}(", def.name)),
            "[{}] wrong or missing function name", def.name);
        assert!(emitted.contains("-> u32"),
            "[{}] wrong return type", def.name);
    }
}
