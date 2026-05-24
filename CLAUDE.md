# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build          # compile
cargo run --bin demo # run verification harness + print a concretization dump
cargo test           # unit tests (vm, lower)
cargo test --features fixture-defs                  # + emit integration tests
cargo run --bin regen_fixtures --features fixture-defs  # regenerate fixture files
```

## What This Is

**xorpl** is a Rust compiler that produces obfuscated client-side code for checksumming browser events. The output is evidence that code actually ran in a real browser. No fingerprinting—just checksumming hardcoded events.

The project implements analytics integrity for `fiolin` using a masking scheme based on XOR over GF(2).

## Architecture

Two conceptual layers:

1. **Value graph (`Circuit`)** — a salt-free dataflow DAG of gadgets defining the mixing function `F`. The server can mirror this exactly to verify integrity.
2. **Concretization** — given a seed, the compiler decorates every wire with a concrete XOR mask and emits baked constants. Rotating the VM means re-running concretization with a new seed.

### Masking Scheme

Each logical value `X` is stored as `X ^ m` where `m` is a salt-derived mask constant:

- **Free (linear) ops**: XOR, rotation, shift, NOT — masks propagate analytically for free.
- **Metered (nonlinear) ops**: Bitwise AND is the only hard primitive. Each AND gate consumes a **Beaver-style triple** (`(a, b, a&b)` masked). One fresh triple per nonlinear output — no reuse.

### Gadget Catalog (11 types)

| Category | Gadgets |
|----------|---------|
| Sources | `PUBLIC_CONST`, `SECRET_CONST`, `INGEST` |
| Linear | `XOR`, `XOR_CONST`, `AND_CONST`, `ROTL` |
| Nonlinear | `AND` (sole triple consumer) |
| Utility | `REMASK`, `EGRESS` |

Control flow is handled via if-conversion/predication (branches become MUX). Only bounded loops are supported (unrolled to worst-case with gated predicates for constant-time execution).

### Key Types (`src/vm.rs`)

- `Wire` / `WireRole` — typed wire with role (value, mask, constant delta, triple component)
- `Gadget` — enum of all 11 gadget kinds + their inputs/outputs
- `Circuit` — the salt-free value graph (list of gadgets + I/O wire sets)
- `Generator` — one PRNG-seeded generator per nonlinear output / secret const / ingest
- `ConcreteVm` — result of concretization: masked gadget schedule + constant pool + triple pool

### Core Methods

- `Circuit::eval()` — evaluates the unmasked function F (server-side spec)
- `ConcreteVm::from_circuit()` — concretization pipeline: mask propagation → triple allocation → constant baking
- `ConcreteVm::eval()` — masked register evaluation (proves `register == value ^ mask` for all wires)

### Concretization Pipeline

1. Build value graph (F + if-converted control flow)
2. Allocate generators (one per AND output, secret const, ingest wire)
3. Seed PRNG; sample all generators → rotation key
4. Topological mask-propagation pass
5. Bake constants: triples, mask deltas, secret values
6. Register-allocate and freeze schedule
7. Emit: instructions + constant pool + triple pool + I/O descriptors

### Key Invariants

- **No triple reuse**: one generator per nonlinear AND output
- **Non-degeneracy**: no secret-carrying wire lands on zero mask
- **Public/secret separation**: only `SECRET_CONST` perturbs masks; public constants don't
- **Data-independent schedule**: no control flow that leaks timing

### Test Circuit (in `demo.rs`)

`F(a, b) = rotl((a | b) ^ C, 5)` where `C = 0x9e3779b9` (secret constant). Exercises ingestion masking, the metered AND (via `a | b = (a ^ b) ^ (a & b)`), secret-constant obscuring, and rotation.

### Verification Harness (`verify()` in demo)

Runs 200 concretizations × 20 random inputs (4,000 total masked executions). Asserts:
1. Egress reveals exactly F's plaintext output
2. Every register holds `value ^ mask`
3. Ingested inputs never appear raw
4. No triple reuse

## Word-Level Optimization

Word-level AND (operating on u32) reduces the triple cost versus bit-level AND: ~31 triples per word-AND vs. ~61 for bit-level. The compiler chooses word vs. bit-level lowering during optimization.

## Rotation

**Cheap rotation**: re-run concretization with a new seed (same structure, fresh constants).  
**Strong rotation**: also re-randomize structure (reassociate trees, reorder gadgets, swap lowerings, add decoys) so successive images share no recognizable patterns.

## Stack

- Rust 2021 edition
- One dependency: `rand = "0.9.1"`
- Target: eventually emits raw Rust (`Vec<u32>` operations) deployable in Cloudflare Workers
