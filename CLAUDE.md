# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build                                             # compile
cargo test                                              # unit + integration tests
cargo test --features fixture-defs                      # + emit integration tests
cargo run --bin regen_fixtures --features fixture-defs  # regenerate fixture files
cargo run --bin demo                                    # verification harness + concretization dump
```

Single test: `cargo test test_name` or `cargo test module::test_name`.

## What This Is

**xorpl** is a Rust compiler that produces obfuscated client-side code for checksumming browser events. The output is evidence that code actually ran in a real browser. No fingerprinting—just checksumming hardcoded events.

The project implements analytics integrity for `fiolin` using a masking scheme based on XOR over GF(2).

## Module Map

| Module | Purpose |
|--------|---------|
| `src/expr.rs` | `Expr` — high-level expression tree (inputs, constants, XOR, AND, ROTL, etc.) |
| `src/expr_transform.rs` | `strong_rotate` and supporting passes (constant_fold, reassociate, inject_decoys, apply_identities) |
| `src/lower.rs` | `lower_to_circuit(&expr) -> Circuit` — converts `Expr` tree to flat gadget DAG |
| `src/circuit.rs` | `Circuit` — salt-free value graph; `Circuit::eval()` (server spec) |
| `src/circuit_transform.rs` | Post-lowering passes: `inject_remasks`, `split_secret_consts` |
| `src/mask.rs` | `MaskedCircuit::from_circuit()` — concretization: mask propagation, triple allocation, constant baking |
| `src/emit.rs` | `emit_rust()` (obfuscated browser source), `emit_verifier_rust()` (plaintext server source) |
| `src/pipeline.rs` | `compile()` orchestrates all stages; `rotate_cheap()`; `Compilation` struct |
| `src/prelude.rs` | Re-exports for downstream crates (`use xorpl::prelude::*`) |
| `src/fixture_defs.rs` | `ALL_FIXTURES` — fixture definitions for skew/structural tests (feature-gated) |
| `src/bin/regen_fixtures.rs` | Binary to regenerate `tests/fixtures/*.rs` |
| `src/bin/demo.rs` | Verification harness: 200 rotations × 20 inputs |

## Pipeline Stages

```
Expr
 └─► expr_transform::strong_rotate      (optional; for strong rotation)
      └─► lower::lower_to_circuit
           └─► circuit_transform::inject_remasks + split_secret_consts
                └─► mask::MaskedCircuit::from_circuit   (concretization)
                     ├─► emit::emit_rust                (browser Wasm source)
                     └─► emit::emit_verifier_rust       (server Wasm source, from Circuit directly)
```

`pipeline::compile()` wires all stages. `rotate_cheap()` reruns only `from_circuit` + `emit_rust` with a new RNG, keeping the same `Circuit` (and thus the same `EXPR_DIGEST`).

## Masking Scheme

Each logical value `X` is stored as `X ^ m` where `m` is a salt-derived mask constant:

- **Free (linear) ops**: XOR, rotation, NOT — masks propagate analytically at zero cost.
- **Metered (nonlinear) ops**: AND is the only hard primitive. Each AND gate consumes one **Beaver-style triple** (`T = (mx & my) ^ mz`). One triple per gate, never reused.

### Gadget Catalog

| Category | Gadgets |
|----------|---------|
| Sources | `PUBLIC_CONST`, `SECRET_CONST`, `INGEST` |
| Linear | `XOR`, `XOR_CONST`, `AND_CONST`, `ROTL` |
| Nonlinear | `AND` (sole triple consumer) |
| Utility | `REMASK`, `EGRESS` |

## Key Types

- **`Circuit`** (`src/circuit.rs`) — salt-free gadget DAG. `pub fn eval(&self, inputs) -> u32` is the server-side reference spec.
- **`MaskedCircuit`** (`src/mask.rs`) — result of concretization: concrete masks + constant pool + triple pool.
- **`Compilation`** (`src/pipeline.rs`) — output of `compile()` with fields: `original_expr`, `circuit: Circuit`, `masked: MaskedCircuit`, `code: String`, `expr_digest: [u8; 32]`.
- **`Expr`** (`src/expr.rs`) — expression tree for building circuits before lowering.

## Emitted Output

Both emitters embed `pub const EXPR_DIGEST: [u8; 32] = [...];` (SHA-256 or HMAC-SHA-256 of the original expression before any transforms).

- `emit_rust(masked, circuit, fn_name, rng, digest)` — obfuscated output for the browser. Includes `const POOL`, Beaver triple expansion, register shuffling via linear-scan allocation with emit-seed shuffle.
- `emit_verifier_rust(circuit, fn_name, digest)` — plaintext DAG walk for the server. No POOL, no triple expansion. `Remask` gadgets emit as identity `let wN = wM`. Parameters use `input_{name}` prefix to avoid collision with `w{N}` intermediates.

## Key Invariants

- **No triple reuse**: one `GenId` per AND output, enforced by `Circuit::validate()`
- **Non-degeneracy**: no secret-carrying wire lands on zero mask
- **Public/secret separation**: only `SECRET_CONST` perturbs masks; public constants don't
- **Data-independent schedule**: no branching on masked values

## Rotation

**Cheap rotation**: `rotate_cheap(&compilation, fn_name, rng)` — reruns concretization with a new seed. Same `Circuit`, same `EXPR_DIGEST`. Server verifier does not change; no server redeploy needed.

**Strong rotation**: rebuild from `Expr` → `expr_transform::strong_rotate` → `lower_to_circuit` → `compile`. New `Circuit`, same `EXPR_DIGEST` (digest is from the original expression, not the circuit). Server verifier does not change; no server redeploy needed.

### AST Transforms (`src/expr_transform.rs`)

`strong_rotate` pipelines five passes:

| Pass | What it does |
|------|-------------|
| `constant_fold` | Evaluate constant sub-expressions; simplify identities (`x^0=x`, `x&0=0`, etc.) |
| `reassociate` | Flatten XOR/AND chains, shuffle operand order, re-bracket randomly |
| `inject_decoys` | Splice dead sub-expressions to pad AND-triple count |
| `apply_identities` | Randomly apply De Morgan, double-NOT introduction/removal, XOR flip |
| `constant_fold` | Clean up noise introduced by identity rewrites |

`decoy_xor_zero` and `decoy_mux` are exposed as public helpers for deterministic decoy construction (used in fixture builders).

## Word-Level Optimization

`Builder::add32` uses a word-level generate optimization: one AND triple for all 32 generate bits, plus 30 triples for the carry chain — 31 triples total vs ~61 for a naive bit-serial adder.

## Downstream Deployment Pattern

Two thin crates import `xorpl` and produce Wasm targets:

- **Browser crate**: calls `compile()`, writes `emit_rust` output to a `.rs` file, and exposes `#[no_mangle] pub extern "C" fn compute(...)` to JS.
- **Server crate**: calls `emit_verifier_rust()` on the same `Circuit`, exposes the same signature as the browser function. The verifier is plain arithmetic — no POOL, no triples.

Both compile to `wasm32-unknown-unknown`. For existing Cloudflare Workers (JS/TS), bind the Wasm via `[wasm_modules]` in `wrangler.toml`; instantiate with `new WebAssembly.Instance(env.VERIFIER)` and call `instance.exports.fn_name(a, b)`.

The `EXPR_DIGEST` in both Wasm artifacts is the link: the server uses it to look up the right verifier and to key the D1 replay filter.

## Fixture System

Tests live in `tests/fixtures/<name>.rs`, managed by `tests/emit_tests.rs` (requires `--features fixture-defs`):

- **Correctness** (`gives_right_answer`): includes the fixture source and calls the emitted function on known inputs.
- **Skew check** (`fixtures_not_out_of_sync`): re-emits every fixture and diffs against disk. Run `regen_fixtures` after changing the emitter.
- **Structural** (`structural_properties`): checks for `pub const EXPR_DIGEST`, `const POOL`, correct function signature.

When adding a fixture: add a definition to `src/fixture_defs.rs`, add a test block in `tests/emit_tests.rs`, run `regen_fixtures`.
