# Changelog

All notable changes to this project are documented here. The public API follows
[semantic versioning](https://semver.org/); pre-1.0 minor bumps may introduce
breaking changes.

## [Unreleased]

### Added

- **C ABI for the Binius STARK** (`src/capi.zig`, `zig-capi.h`): a fixed
  `Gf256`/`Gf2_128`/`CommittedMlePcs` instantiation exposing `zs_binius_prove`,
  `zs_binius_verify`, `zs_free` and `zs_version` over the canonical serialized
  wire format, with a host-supplied allocator (ctx + alloc/free callbacks) that
  wraps the alignment/header handling. Round-trip and tamper tests run the full
  vtable path under the leak-checking allocator. A `zig build wasm` step emits a
  `wasm32-freestanding` module (~64 KB ReleaseSmall) exporting the four symbols
  for Node.js / browsers.
- **Fuzz** (`tests/fuzz.zig`, `zig build fuzz`): randomized RangeCheck / Compare
  / Adder iterations that prove+verify valid witnesses and reject a tampered
  serialized proof, leak-checked. (Rejection uses a flipped proof byte rather
  than a witness tamper, which the zero-check can miss in a small field.)
- **CI jobs**: wasm C-ABI build and the gadget fuzz, plus the existing suite now
  also runs in ReleaseFast.
- **JS/WebAssembly binding** (`bindings/js/`, `zig build wasm`): a
  `wasm32-freestanding` module that imports host `zig_stark_malloc`/`free` and
  exposes `zs_binius_prove_wm` / `zs_binius_verify_wm` / `zs_binius_commit_wm` /
  `zs_free_wm` (the wire format pins `usize` to 8 bytes, so it is portable
  across 32/64-bit targets). The ESM/CJS/TypeScript wrapper (`index.mjs`,
  `index.cjs`, `index.d.ts`) provides `proveColumns` / `verify` over the generic
  constraint interface; a Node smoke test proves+verifies a booleanity statement
  and rejects a tampered proof. Docs in `docs/api.md`.
- **Parallel prover** (`core.pool.Pool`, `BiniusStarkWith.proveParallel`):
  `src/core/pool.zig` is a small fork-join executor over `std.Thread.spawn` /
  `join` (Zig 0.16 removed `std.Thread.Pool`) with a comptime single-threaded
  fallback for wasm. `stark.zig`'s prover now parallelizes per-column
  commitments, the combined zero-check sum-check rounds (per-position partials),
  and per-column eval openings; `sumcheck.zig` gained
  `proveCombinationParallel`. ~4x at 8 threads on an 8-core machine
  (`zig build bench-binius`), leak-free, with an e2e round-trip test.
- **Node.js N-API addon** (`bindings/node/addon.zig`, `zig build node-addon`):
  a native `.node` addon exposing `proveColumns` / `verify` with the same
  serialized wire-format inputs as the wasm binding (plus a `version` helper).
  It reuses the C ABI (`zs_binius_prove` / `zs_binius_verify` / a new native
  `zs_binius_commit`) with a per-call arena-backed host allocator; the addon's
  `Host` avoids a dangling-allocator bug by rebuilding the arena allocator per
  callback. Smoke test in `bindings/node/test/smoke.mjs`.
- **CUDA (E0a, experimental)** (`src/cuda/`): minimal CUDA Driver API bindings
  (`extern "c"`, since `@cImport("cuda.h")` mislinks on Zig 0.16) + a
  `Cuda` context helper. A `vecAdd` validation kernel is compiled to PTX by
  `nvcc` and embedded/loaded via `cuModuleLoadData` / `cuLaunchKernel`;
  `zig build cuda-hello` runs it (GPU result compared to CPU) and
  `zig build cuda-kernels` regenerates the PTX. Documented that Zig 0.16's
  nvptx backend cannot emit loadable kernels, so CUDA C + Driver API is the
  path. `Cuda.init` fails cleanly without a GPU/driver (CPU fallback).

- **CI** (`.github/workflows/ci.yml`): `zig build fmt`, `zig build`, and
  `zig build test` on every push/PR, on Zig 0.16.0 stable via
  `ziglang/setup-zig`; CI badge in the README.
- **`Dockerfile`**: reproducible build image pinning Zig 0.16.0 from
  ziglang.org (SHA-256 verified) that runs `zig build test`.
- **`LICENSE`**: Apache-2.0 (© 2026 Tomás Díaz); the README license section now
  points at it.
- **`docs/api.md`**: consumer-facing API reference (both stacks, PCS backends,
  fields, gadgets) and a minimal external-dependency example
  (`build.zig.zon` → `@import("zig-stark")`).
- **README Benchmarks section**: published circle-FFT and Binius-STARK numbers
  (ReleaseFast, Ryzen 7 5800H) with methodology.

- `src/binius/fripcs.zig`: `Ntt.forwardTransform` is now public, and a new
  `Ntt.inverseForwardTransform` inverts it (reverse layers, inverse butterfly),
  giving the O(2^k·k) interpolation / O(2^D·D) extension primitives of the
  additive FFT in the novel basis. Tests pin `forward ∘ inverse == id` and
  `pack.novelEval == forward` over zero-padded messages.
- `src/binius/pack.zig`: `novelNorms` (comptime novel-basis normalizations
  c_i = s_i(e_i)) and `novelEval` (O(2^k) single-point evaluation in the novel
  basis, the analogue of Horner for the additive NTT).
- `src/core/serialization.zig`: canonical little-endian proof wire encoding.
  `serialize(allocator, value)` / `deserialize(allocator, bytes, T)` derive the
  format from the compile-time type (no per-struct code): field elements as
  `SIZE` LE bytes (the same convention every transcript absorbs), `[N]u8`
  raw, slices with a `u64` LE length prefix, unsigned ints LE (`usize` is 8
  bytes), optionals with a one-byte presence flag, structs in declaration
  order. `std.mem.Allocator` fields never cross the wire (restored on read),
  and `CommittedMlePcs.Proof.owns_entries` is forced true so deserialized
  proofs own their `entries` copy. Covers every proof in both stacks (Binius
  sum-check / PCS / arg / STARK in both eval shapes; M31 FRI / STARK), with
  e2e round-trips proving `prove -> serialize -> deserialize -> verify` is
  accepted for `CommittedMlePcs`, `BatchFriPcs`, both `BiniusArg` backends,
  and the M31 Fibonacci STARK, plus a golden test pinning the byte layout.
  `docs/wire.md` documents the format.
- `src/binius/pcs.zig`: `CommittedMlePcs.Proof` gains `owns_entries: bool =
  false`; `deinit` frees `entries` when set, so serialized proofs remain
  leak-free.
- e2e round-trip tests in `tests/e2e_tests.zig` for all proof shapes above.
- `src/binius/batchpcs.zig`: batched eval PCS (M2). `BatchFriPcs(F, E,
  log_blowup, q)` shares one Merkle tree per FRI layer across all columns
  opened at the same point, so a single query path per round serves every
  column; each column keeps its own eval sum-check and fold challenges, so
  individual claims stay individually bound. `BatchFriPcsStark` mirrors the
  `FriPcsStark` adapter (`commit` per column, plus `proveEvalBatch` /
  `verifyEvalBatch`). `BiniusStarkFri` now uses it: `stark.zig` dispatches on
  `@hasDecl(CP, "proveEvalBatch")` and `Proof.evals` is a tagged union of
  `[]EvalProof` (per-column) or `CP.BatchProof` (batched), cutting the
  dominant per-query Merkle-path section by a factor of `num_columns`.
  `BiniusArgFri` keeps the per-column `FriPcs`.
- `src/binius/bitpack.zig`: a bit-pack gadget for the zero-check STARK. Each
  hypercube point holds one `num_bits`-wide value `v` plus `num_bits` boolean
  bit columns; the constraints are `num_bits` booleanity equations plus one
  pack equation `v = Σ_i b_i·e_i` (a field identity in the tower basis). This
  is the primitive for range checks and bit manipulation. `BitPack(F, E)` and
  `BitPackWith(F, E, CP)` mirror the adder gadget's `generateWitness` /
  `freeWitness` / `result` API.
- `src/binius/rangecheck.zig`: a range-check gadget `RangeCheck(F, E, m)` =
  `BitPack` parameterized by bit count, bounding a committed value in
  `[0, 2^m)` for any `m ≤ F.BITS` (`m + 1` columns, `m + 1` constraints:
  `m` booleanity + one pack). `RangeCheckWith(F, E, m, CP)` swaps in a custom
  PCS.
- `src/binius/compare.zig`: a bit-sliced comparison gadget `Compare(F, E, m)`
  proving `<` / `≤` / `>` / `≥` / `==` between two `m`-bit values. Witness is
  four `m`-wide column groups (bits of `a`, bits of `b`, equality chain `eq`,
  less-than chain `lt`); constraints are the recurrences
  `eq_i = eq_{i+1} ∧ (a_i = b_i)` and
  `lt_i = lt_{i+1} ∨ (eq_{i+1} ∧ a_i < b_i)` (16m constraints, ≤ `14m`
  monomials). The `lt_m = 0` base uses the constant `eq_m = 1`; constant terms
  are sound because the zero-check evaluates `Σ_x C(x)·β_τ(x) = C(τ)` with
  `Σ_x β_τ(x) = 1`.
- `src/binius/constraints.zig`: a comptime constraint DSL for composing
  gadgets in one proof. `Builder(C, n, max_terms)` accumulates constraints
  (`add`, `@"bool"`) into a monomial pool; `finish()` materializes it as a
  comptime const (a comptime `var` cannot be referenced by a global);
  `shiftInto(B, &b, t0, col_offset, src)` appends another gadget's constraints
  with remapped column indices. Used by `examples/binius_rangecmp`.
- `examples/binius_rangecmp`: an end-to-end example composing two range checks
  and one comparison in a single proof (26 columns, 34 constraints: `2·5 +
  16` gadget constraints plus 8 linear value links equating the range-check
  bit columns to the comparison's `a`/`b` columns). Proves a sequence
  `seq[0..n+1]` is strictly increasing with every element in `[0, 16)`;
  `seq[0]` and `seq[n]` are pinned as public boundary assertions.
- `examples/binius_bitpack`: an end-to-end example proving a batch of 16
  8-bit values, with the first value pinned as a public statement.
- `docs/examples.md`: a "Writing a custom Binius gadget" section with a
  choose-your-stack table (`BiniusStark*`, `BiniusArg*`, PCS backends) and the
  `BiniusArg` (product-sum) vs `BiniusStark` (zero-check) distinction.
- `docs/binius.md` §9: a batched-openings design (batched FRI queries, one
  Brakedown-style sumcheck for all eval openings, tower-size-1 packing) as a
  TODO milestone (M2) and is now implemented: shared per-layer FRI trees make
  a single query path per round serve every column.

### Changed

- **Zig 0.16.0 stable.** The repo previously targeted a 0.16.0-dev build;
  the compatibility pass (commit `2e3e0fc`) replaces the dev-era
  `std.heap.GeneralPurposeAllocator` with `std.heap.DebugAllocator` in examples
  and benchmarks and marks never-mutated locals as `const` (batchpcs, fripcs,
  simd test). All 223 tests pass on stable; README, `LESSON_ZIG.md` and
  `build.zig.zon` (already `minimum_zig_version = "0.16.0"`) document it.
- **`src/binius/packed_pcs.zig` now packs rows with the additive NTT instead of
  O(N²) Lagrange interpolation.** `buildRows` uses `inverseForwardTransform`
  (O(2^{k2}·k2)) to put each row into novel-basis coefficients; `buildCodewords`
  uses `forwardTransform` on the zero-padded novel message (O(M log M), M =
  2^{k2+log_blowup}) instead of O(N·M) Horner extension; single-point
  row-combination evaluations use `pack.novelEval`. The interpolating
  polynomials are unchanged (the novel basis represents the same degree-<2^{k2}
  polynomial), so proofs are byte-identical.
- **`src/binius/addfri.zig` packs each FRI fold-pair into one Merkle leaf**
  (`hashPair` hashes the concatenated element bytes once), halving the per-layer
  leaf count and the Blake3 call count; `LayerProof` carries a single `path`
  instead of `path0`/`path1` (proofs and Merkle paths per query halve).

## [0.2.0] - 2026-08-13

### Added

- `src/binius/clmul.zig`: hardware CLMUL-accelerated carry-less multiply for the
  tower-field `mul`/`mulHi`/`inv` fast path, with runtime detection of
  `pclmulqdq` support and a software fallback. Tables are built lazily on first
  use behind a mutex.
- `docs/binius.md`: a "Memory model (caller-deinit convention)" section
  documenting ownership rules for every public `Proof`, `MerkleTree`, and
  builder helper.
- `CHANGELOG.md` and a "Releases" section in the README.

### Changed

- **Breaking:** the Binius STARK and product-sum argument no longer take a
  comptime column/table cap. The `max_cols` / `max_tables` parameters and the
  `MaxColumns` / `MaxTables` constants are removed; all fixed-size arrays sized
  by the cap are now heap-allocated at the actual column count. Signatures:
  - `BiniusStark(F, E)` (was `BiniusStark(F, E, max_cols)`)
  - `BiniusStarkFri(F, E, log_blowup, num_queries)`
  - `BiniusStarkWith(F, E, CP)`
  - `BiniusArg(F, E)` (was `BiniusArg(F, max_tables)`)
  - `BiniusArgFri(F, E, log_blowup, num_queries)`
  - `BiniusArgWith(F, E, CP)`
- **Memory lifetime:** every public `Proof` now owns its heap memory and exposes
  `deinit(self: *Proof, allocator)`, which the caller must invoke with the same
  allocator passed to `prove` / `proveEval` / `commit`. `MerkleTree` carries its
  own allocator. Inputs passed into the API are always borrowed, and `verify`
  never frees proof memory.
- `arg.Proof.evals` is now `[]EvalProof` (mutable) so nested PCS proofs can be
  released.
- All library tests now run against `std.testing.allocator`, so the suite is
  leak-checked end to end.

### Fixed

- `sumcheck.runRounds` leaked `challenges` whenever a round-consistency check
  failed (`errdefer` does not fire on `return null`); this was the normal
  rejection path for any invalid proof. The buffer is now freed before the
  `return null`.
- `stark.prove` leaked the outer `kernelTables` container on the boundary-pin
  path; the pin-kernel `[][]E` wrapper is now freed after its inner tables are
  moved into the shared table pool.

## [0.1.0] - 2026-08-12

Initial release: M31 DEEP-FRI STARK stack (Fibonacci / Rescue / linear-ML
examples), Binius/BSV binary-field stack over the canonical Wiedemann tower of
GF(2^k) with zero-check STARK, committed-MLE / packed / polylog FRI-Binius PCS,
standalone product-sum argument, and a batched 4-bit adder gadget.
