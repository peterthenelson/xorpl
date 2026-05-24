# XORPL — Obfuscated Attestation Compiler

Compiler that produces obfuscated Rust code for checksumming client-side browser events, as evidence that the event came from a real browser actually running the code. Used for `fiolin` analytics (no fingerprinting or personal information — just a hardcoded list of events and the script name).

## Threat model and its ceiling

The "attacker" is a bot author who holds the entire compiled program and controls the machine it runs on. They can debug it and dump registers and baked-in constants. This is obfuscation, not a cryptographically secure system. What it buys:

- Requests from scrapers that don't run a VM at all are filtered out.
- The checksumming circuit can be rotated more cheaply than it can be reverse-engineered.
- Per-request nonces can anchor a replay-filtering scheme on the server.

## Masking scheme

A logical value `X` lives in a register as `X ^ m` for a mask `m` (a salt-derived constant). The scheme is affine over GF(2), which cleanly splits operations:

- **Free (linear/affine).** XOR, NOT, rotations, shifts, AND/XOR with a public constant, remasking. The mask transforms by the same function as the value and tags along automatically.
- **Metered (nonlinear).** Bitwise AND of two masked values is the only hard primitive. It is realized with a precomputed Beaver-style triple and a fresh output mask; everything else (OR, ADD, MUX) composes from `{XOR, AND, NOT}`.

The nonlinearity matters for integrity: a function built only from free ops is GF(2)-linear and could be recovered from a handful of (input, output) samples by Gaussian elimination. Triples are exactly the algebraic resistance to that.

### The masked-AND gadget

To compute `z = (X & Y) ^ mz` from `x = X^mx`, `y = Y^my`, with a per-gate triple `T = (mx & my) ^ mz`:

```
z = T
z = z ^ (x & my)   # AND with a compile-time constant — free
z = z ^ (y & mx)   # free
z = z ^ (x & y)    # the one real masked AND
# z == (X & Y) ^ mz
```

Only the final line combines two live masked registers. Because concretization already knows each operand's mask, the triple is minted to fit whatever masks the operands carry. **Each AND owns a fresh output mask; triples are never reused** (reuse leaks the relationship between the masked values).

## Usage

```rust
use xorpl::prelude::*;

// Build an expression.
let a = Expr::input("a");
let b = Expr::input("b");
let c = Expr::secret_const(0x9e37_79b9);
let expr = Expr::rotl(Expr::xor(Expr::or(a, b), c), 5);

// Compile to obfuscated browser source + server verifier source.
let mut rng = rand::rngs::StdRng::seed_from_u64(42);
let compilation = compile(&expr, "my_fn", &mut rng);

println!("rotation tag: {:08x}", compilation.rotation_tag);
println!("browser source:\n{}", compilation.code);

let verifier_source = emit_verifier_rust(&compilation.circuit, "my_fn_verify");

// Cheap rotation: new masks, same circuit structure, same rotation tag.
let (_, new_code) = rotate_cheap(&compilation, "my_fn", &mut rng);
```

Both `compilation.code` and `verifier_source` are valid Rust files that compile to `wasm32-unknown-unknown`. The emitted function signature is `pub fn <name>(...) -> u32`. Both embed `pub const ROTATION_TAG: u32 = 0x...;` so the server can match browser submissions to the right verifier.

## Gadget catalog

| Gadget | Cost | Mask transfer | Notes |
|--------|------|---------------|-------|
| `PUBLIC_CONST k` | free | 0 | `k` baked into pool |
| `SECRET_CONST k` | free | fresh gen `m` | `k ^ m` baked; server never sees `m` |
| `INGEST` | free | fresh gen `m` | `m` baked; raw input never appears |
| `XOR` | free | `ma ^ mb` | — |
| `XOR_CONST k` | free | `ma` | — |
| `AND_CONST k` | free | `ma & k` | — |
| `ROTL` | free | rotate(`ma`) | — |
| `AND` | 1 triple | fresh gen `mz` | Beaver triple `T, ma, mb` baked |
| `REMASK` | free | fresh gen | delta baked |
| `EGRESS` | free | — | unmask delta baked |

## Compiler architecture

Two layers:

1. **Value graph (`Circuit`).** A salt-free dataflow DAG of gadgets that *is* the mixing function `F` plus already-predicated control flow. The server mirrors this exactly — masks cancel, so value semantics are identical. `Circuit::fingerprint()` is a stable FNV-1a hash of the structure.
2. **Concretization.** Given a seed, decorate every wire with a concrete mask and emit all baked constants. Rotating is just re-running concretization with a new seed.

### Pipeline

```
Expr
 └─► expr_transform::strong_rotate   (optional; for strong rotation)
      └─► lower::lower_to_circuit
           └─► circuit_transform::inject_remasks + split_secret_consts
                └─► MaskedCircuit::from_circuit   (concretization)
                     ├─► emit_rust                (browser Wasm source)
                     └─► emit_verifier_rust       (server Wasm source)
```

### Rotation strengths

- **Cheap:** `rotate_cheap()` reruns concretization with a new seed — same circuit structure, fresh constants, same `ROTATION_TAG`. Server verifier is unchanged; only the browser Wasm redeploys.
- **Strong:** rebuild from `Expr` through `expr_transform::strong_rotate` — new gadget structure, new `ROTATION_TAG`. Both browser and server Wasm redeploy.

Strong rotation applies five AST passes: constant folding, reassociation, decoy injection, identity rewrites (De Morgan, double-NOT, XOR flip), and a second constant fold pass to clean up.

### Word-level optimization

`Builder::add32` computes all 32 generate terms `a_i & b_i` in a single word AND, leaving only the sequential carries — 31 triples total vs ~61 for a naive bit-serial adder.

## Deployment

The intended downstream pattern is two thin crates that import `xorpl`:

- **Browser crate** — calls `compile()`, includes the emitted source, exposes `#[no_mangle] pub extern "C" fn compute(...)` to JavaScript.
- **Server crate** — calls `emit_verifier_rust()` on the same `Circuit`, exposes the same signature. Plain arithmetic, no obfuscation overhead.

Both compile to `wasm32-unknown-unknown`. An existing Cloudflare Worker (JS/TS) can bind the Wasm via `[wasm_modules]` in `wrangler.toml` and call `instance.exports.fn_name(a, b)`. The server matches `ROTATION_TAG` in the request to the right compiled-in verifier function, and keys D1 replay filtering on `(rotation_tag, checksum)`.

## Stack

- Rust 2021 edition
- One dependency: `rand = "0.9.1"`
- Output: raw Rust operating on `u32` values, deployable as `wasm32-unknown-unknown`
