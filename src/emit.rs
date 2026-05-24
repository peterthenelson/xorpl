//! Emission: `ConcreteVm` → Rust source code.
//!
//! This module takes a baked, concrete VM and emits a standalone Rust function
//! that implements the same computation without any VM machinery — just array
//! accesses, XOR, AND, and rotation on `u32` values.
//!
//! The emitted function is what gets shipped to the client (compiled to Wasm
//! or included in a JS bundle). A new rotation means re-running
//! `ConcreteVm::from_circuit` with a new seed and re-emitting; the circuit
//! structure stays the same, only the constants change.
//!
//! # Emitted shape
//!
//! ```rust,ignore
//! pub fn checksum(a: u32, b: u32) -> u32 {
//!     const POOL: &[u32] = &[0xdeadbeef, 0xcafebabe, /* ... */];
//!     let mut r = [0u32; N];           // N = number of non-egress wires
//!
//!     // One block per gadget, in topological order:
//!
//!     r[0] = a ^ POOL[0];              // INGEST "a"
//!     r[1] = b ^ POOL[1];              // INGEST "b"
//!     r[2] = POOL[2];                  // SECRET_CONST  (k^mask baked in)
//!     r[3] = r[0] ^ r[1];             // XOR  (free)
//!     r[4] = {                         // AND  (Beaver triple expansion)
//!         let (t, ma, mb) = (POOL[3], POOL[4], POOL[5]);
//!         let mut z = t;
//!         z ^= r[0] & mb;
//!         z ^= r[1] & ma;
//!         z ^= r[0] & r[1];
//!         z
//!     };
//!     // ...
//!     r[K] ^ POOL[M]                   // EGRESS: XOR with unmask delta
//! }
//! ```
//!
//! # Register allocation
//!
//! The initial implementation uses a direct 1:1 mapping: WireId N → `r[N]`.
//! This is correct and simple — array size equals the number of non-egress
//! wires. A future live-range allocator could reduce the array to
//! O(max-live-wires) slots, shrinking the emitted function's stack frame for
//! large circuits (e.g. a full ChaCha double-round with 500+ gadgets).
//!
//! # Constant pool layout
//!
//! Constants are emitted in gadget order, concatenated into a single `POOL`
//! slice. Each gadget records how many pool entries it owns (already tracked
//! in `BakedGadget::consts`), so indexing is straightforward.
//!
//! # Future: structured output
//!
//! The current design returns a `String`. If the emission target changes (e.g.
//! emitting JavaScript or Wasm bytecode directly), this function's signature
//! should change to return a `proc_macro2::TokenStream` or a target-specific
//! IR, keeping the gadget-walking logic intact.

use crate::vm::ConcreteVm;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Emit a self-contained Rust function for the given concrete VM.
///
/// `fn_name`    — the name of the emitted function.
/// `param_names` — ordered list of input names matching the circuit's ingests
///                 (must be valid Rust identifiers).
///
/// Returns a `String` containing a Rust function definition that can be
/// written to a file and compiled independently of this crate.
pub fn emit_rust(
    _vm:          &ConcreteVm,
    _fn_name:     &str,
    _param_names: &[&str],
) -> String {
    todo!()
}

// ---------------------------------------------------------------------------
// Internal helpers (stubs)
// ---------------------------------------------------------------------------

// Planned:
//
// fn build_pool(vm: &ConcreteVm) -> (Vec<u32>, Vec<usize>)
//   Flatten BakedGadget::consts into a single pool Vec and return a
//   parallel Vec of starting indices so gadget i's constants are
//   pool[starts[i]..starts[i+1]].
//
// fn emit_gadget(gadget_idx: usize, vm: &ConcreteVm, pool_starts: &[usize])
//         -> String
//   Emit the Rust statement(s) for one gadget.  AND emits the four-line
//   Beaver expansion; all other gadgets are a single assignment.
//
// fn emit_signature(fn_name: &str, param_names: &[&str]) -> String
//   Emit `pub fn <name>(<p0>: u32, <p1>: u32, ...) -> u32 {`
