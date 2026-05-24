# XORPL -- Obfuscated Attestation

Compiler for producing obfuscated code to checksum client-side event data, as
evidence that the event came from a real browser actually running the code.
Used for `fiolin` analytics (note: no fingerprinting or personal information,
just a hardcoded list of events and the script name!).

## Threat model and its ceiling

The "attacker" is a bot author who holds the entire compiled program and
controls the machine it runs on. They can debug it and dump registers and
baked-in constants. This is therefore obfuscation, not a cryptographically
secure system. What it buys:
- Requests from scrapers that don't run a VM at all will be filtered out.
- Per-request nonces can be used as part of a scheme to filter out replayed
  or precomputed requests.
- All of obfuscation (or the details of the checksumming circuit) can be
  rotated more cheaply than debugging the obfuscated circuit.

## Masking scheme

A logical value `X` lives in a register as `X ^ m` for a mask `m` (a salt-derived
constant). The scheme is affine over GF(2), which cleanly splits operations:

- **Free (linear/affine).** XOR, XOR/AND with a public constant, NOT, rotations,
  shifts, fixed bit-permutations, remasking. The mask transforms by the *same*
  function as the value and tags along automatically.
- **Metered (nonlinear).** Bitwise AND of two masked values is the only hard
  primitive. It is realized with a precomputed Beaver-style triple and a fresh
  output mask; everything else (OR, ADD, SUB, MUL, comparisons, MUX) composes
  from `{XOR, AND, NOT}`.

The nonlinearity matters for integrity, not just cost: a function built only
from free ops is GF(2)-linear and could be recovered from a handful of
(input, output) samples by Gaussian elimination. The triples are exactly the
algebraic resistance to that.

### The masked-AND gadget

To compute `z = (X & Y) ^ mz` from `x = X^mx`, `y = Y^my`, with a per-gate triple
`T = (mx & my) ^ mz`:

```
z = T
z = z ^ (x & my)   # AND with a compile-time constant — free
z = z ^ (y & mx)   # free
z = z ^ (x & y)    # the one real masked AND
# z == (X & Y) ^ mz
```

Only the final line combines two live masked registers. Because concretization
already knows each operand's mask, the triple is *minted to fit* whatever masks
the operands carry, so pre-remasking is rarely needed. **Each AND owns a fresh
output mask; triples are never reused** (reuse leaks the relationship between the
masked values).

## Mixing function `F`

`F(nonce, event)` is an ARX construction (add–rotate–xor), e.g. a ChaCha-style
quarter round over a 4-word state. ARX maps onto the cost split almost perfectly:
rotates and XORs are free, and only the adds consume triples.

A ripple-carry `ADD32` costs ~61 triples (two masked ANDs per full-adder bit,
minus the free bit-0 propagate and the unneeded top carry). The word-level
optimization — compute all 32 generate terms `a_i & b_i` in a single word AND,
leaving only the sequential carries — drops this to ~31 triples. Total VM cost is
roughly `504 * R` triples for `R` double-rounds; `R = 2`–`3` is ample for a
non-cryptographic attestation.

## Compiler architecture

Two layers that barely interact:

1. **Value graph (`Circuit`).** A salt-free dataflow DAG of gadgets that *is* `F`
   plus already-predicated control flow. It encodes only what is computed. The
   **server mirrors this exactly** — masks cancel, so value semantics are
   identical — which keeps client and server in sync for free.
2. **Concretization.** Given a seed, decorate every wire with a concrete mask and
   emit all baked constants. Rotating the VM is just re-running this with a new
   seed; the structure stays, only the numbers change.

Every gadget defines four parallel transfer functions: `value` (the spec, also
the server), `mask` (how masks flow), `constants` (baked image constants), and
`lower` (the masked-register instructions).

### Gadget catalog

| Gadget | Cost | Mask transfer | Bakes |
| --- | --- | --- | --- |
| `PUBLIC_CONST k` | free | 0 | `k` |
| `SECRET_CONST k` | free | fresh gen `m` | `k ^ m` |
| `INGEST` | free | fresh gen `m` | `m` |
| `XOR` | free | `ma ^ mb` | — |
| `XOR_CONST k` | free | `ma` | `k` |
| `AND_CONST k` | free | `ma & k` | `k` |
| `ROTL/SHL/SHR/PERM` | free | permute(`ma`) | — |
| `AND` | 1 triple | fresh gen `mz` | `T, ma, mb` |
| `REMASK` | free | fresh gen | delta |
| `EGRESS` | free | — | unmask delta |

Composite gadgets (`OR`, `SELECT/MUX`, `FULLADD`, `ADD32`, `MUL`, the quarter
round) expand to the above, or provide their own optimized `mask`/`constants`/
`lower` (e.g. the word-generate `ADD32`).

### Information carried

- **Per wire:** id, width, producing gadget + port, role (`ingest` / `egress` /
  `internal` / `loop-carried`). The concrete mask is filled in during
  concretization and stored in a side map, keeping the graph salt-free.
- **Per gadget:** type + static params, input/output wires, the `GenId`s of any
  fresh randomness it owns.
- **Global:** the gadget DAG, the **generator registry** (every independent
  randomness source + width — this plus the seed is the rotation key), the seed
  (kept server-side), register allocation + a data-independent schedule, the
  constant/triple pool layout, ingest/egress descriptors, and the reference `F`
  for the server.

### Concretization pipeline

1. Build the value graph (`F` + predicated, bounded-unrolled control flow).
2. Optimize on values: constant-fold, DCE, choose word- vs bit-level ANDs, fix a
   data-independent schedule.
3. Allocate one generator per nonlinear output / `SECRET_CONST` / `INGEST`.
4. Seed the PRNG and sample every generator.
5. Mask-propagation pass: topologically evaluate each wire's mask.
6. Constant-emission pass: emit triples, operand-mask constants, remask deltas,
   secret-const values, IV.
7. Register-allocate; freeze the schedule.
8. Emit the image: instructions + constant pool + triple pool + ingest/egress
   descriptors. The server keeps only the value graph and the per-session nonce.

### Invariants

- One generator per nonlinear output ⇒ **no triple reuse** by construction.
- **Non-degeneracy:** no secret-carrying wire lands on a zero (or zero-on-secret-
  bits) mask, and no two distinct secret wires share a trivially-cancelling mask;
  re-seed if so (rare, cheap to check).
- Public vs secret constants kept strictly distinct — only `SECRET_CONST`
  perturbs a mask, or propagation desyncs from emission.
- The instruction schedule is **data-independent** (control flow already
  if-converted to MUX) so the execution trace leaks nothing.

## Control flow

Branching on hidden data would leak via the execution path, so control flow is
compiled to data flow via **if-conversion / predication**: run all paths, select
results with `MUX`. SSA phi nodes become `SELECT`s driven by edge predicates;
nested branches propagate predicates (`AND c` / `AND ~c`, merges via `XOR`).

Loops are the limitation: only **bounded** loops are expressible. Each is unrolled
to a static maximum and gated by a per-iteration "running" predicate, so it
always runs worst-case (constant-time — good for obliviousness, costly for
performance). Side effects on untaken paths must be neutralized; secret-indexed
memory needs oblivious access. Unbounded loops cannot be compiled to pure MUX.
The compiler will not likely support loops at all.

## Rotation strengths

- **Cheap:** re-run concretization with a new seed — same structure and schedule,
  fresh constants. A cracked image is valid only until the next reseed.
- **Strong:** also re-randomize structure before allocation (reassociate XOR
  trees, reorder independent gadgets, swap `ADD32` lowerings, splice in decoy
  gadgets dropped at egress) so two images don't share a shape.

Both are mechanical because the value graph is the fixed point and everything
salt-dependent is regenerated.

## Status

A reference concretizer + verification harness exists. The harness confirms,
across many rotations and inputs, that egress reveals exactly the plaintext
that the original circuit computed, that every register holds `value ^ mask`,
that ingested inputs never appear raw, and that triples are never reused.

## Open / next

- Builder API so circuit can be written as ordinary expressions and lowered to
  gadgets.
- Automatic generator of a variety of circuits, including randomly adding
  decoy gagets, randomly applying equivalent transformations, as well as
  legitimately computing different checksums (should still have decent mixing
  properties though).
- Register allocator + schedule pass between concretize and emit. Should take
  rng seed as an argument so we can randomize this as part too.
- Final emitter pass that can output raw Rust (operating on a Vec of u32s).
- Server side code deployable in a cloudflare worker.