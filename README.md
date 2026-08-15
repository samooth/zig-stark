# zig-stark

[![CI](https://github.com/samooth/zig-stark/actions/workflows/ci.yml/badge.svg)](https://github.com/samooth/zig-stark/actions/workflows/ci.yml)

A STARK (Scalable Transparent Argument of Knowledge) proof system implemented in Zig, with two stacks: a DEEP-FRI STARK over the M31 / CM31 / QM31 field tower (Mersenne prime fields), and a Binius/BSV-style binary-field stack over the canonical tower of GF(2^k) using zero-check constraints enforced by sum-check with Merkle-committed multilinear polynomials.

## Status

Working end-to-end on both stacks:

- **M31 DEEP-FRI STARK** — the prover and verifier in `src/m31/stark.zig` handle any AIR implementing the `GenericStark` interface, including optional preprocessed columns and **LogUp multiset lookups**, with three complete examples: a Fibonacci sequence, a Rescue permutation, and a single linear ML layer.
- **Binius binary-field stack** — a zero-check STARK (`src/binius/stark.zig`) over the canonical Wiedemann tower of binary fields (`src/binius/tower.zig`), combining committed multilinear PCS openings via sum-check (`src/binius/sumcheck.zig`, `src/binius/pcs.zig`), with an additive FRI low-degree test (`src/binius/addfri.zig`), a standalone product-sum argument (`src/binius/arg.zig`, now `(F, E, PCS)`-parameterized like the STARK), and a gadget library built on bit-sliced encodings: a batched 4-bit ripple-carry adder (`src/binius/adder.zig`), a bit-pack gadget (`src/binius/bitpack.zig`), and new `RangeCheck` / `Compare` gadgets (`src/binius/rangecheck.zig`, `src/binius/compare.zig`) that prove a value fits in `2^m` and compare two bit-sliced values in field arithmetic (with a constant `eq_m = 1` base, sound because the zero-check evaluates `C(τ)`) — combinable in one proof through a small comptime constraint DSL (`src/binius/constraints.zig`), each demonstrated by an end-to-end example. The STARK is parameterized over field, extension field, and the committed-MLE PCS (`CommittedMlePcs` opens all 2^k entries; the `PackedPcs` mode in `src/binius/packed_pcs.zig` commits each witness column as a *packed* univariate polynomial via a column-Merkle tree, opening only the row combination and a handful of sampled columns for sub-linear proofs). The **polylog FRI-Binius PCS** (`src/binius/fripcs.zig`, wired in as `BiniusStarkFri` / `BiniusArgFri`) FRI-folds the additive-NTT code in lockstep with the eval sum-check for O(polylog) proof size, and `BiniusStarkFri` additionally batches all distinct column openings into one proof with shared per-layer Merkle trees (`src/binius/batchpcs.zig`). It supports boundary pins (public column-point evaluations folded into the zero-check, like M31 boundary assertions), and all randomness flows through a single unified Fiat-Shamir channel (`src/core/channel/channel.zig`) that also binds public inputs. The protocol can run over a large extension field `E` (e.g. `tower.Gf2_128`) of a small witness field `F`, keeping ≈ 2^-128 Schwartz-Zippel soundness for script-friendly GF(16)/GF(256) witnesses at the price of `E`-field arithmetic.

223 tests pass (207 unit + 16 end-to-end) with no leaks.

## Documentation

- [`docs/overview.md`](docs/overview.md) — architecture, field tower, module layout, build/test/run instructions
- [`docs/api.md`](docs/api.md) — consumer-facing API reference and how to depend on zig-stark as a library
- [`docs/protocol.md`](docs/protocol.md) — the full DEEP-FRI protocol: composition, quotient, DEEP combination, FRI, and the exact transcript order
- [`docs/examples.md`](docs/examples.md) — how the Fibonacci and linear-ML examples work, and how to write a new AIR
- [`docs/binius.md`](docs/binius.md) — the binary-field stack's soundness: transcript order, every Schwartz-Zippel error term, concrete `(Gf256, Gf2_128)` security, the FRI final-check and packing identities
- [`docs/wire.md`](docs/wire.md) — the canonical little-endian proof wire format (`src/core/serialization.zig`), used by every proof in both stacks
- [`docs/roadmap.md`](docs/roadmap.md) — current status and future work (recursive verification, parallel prover, smaller batch openings, on-chain verification)

## Project structure

```
src/
  core/         Field-agnostic primitives: hash (Blake3), merkle, channel, serialization, pool, simd
  m31/          M31 STARK stack: field tower, circle, ntt, air, poly, fri, stark
    field/      M31, CM31, QM31 field arithmetic + SIMD helpers
    circle/     Circle point group, domains, cosets
    ntt/        Classic NTT, SIMD butterflies, circle FFT (recursive fold)
    air/        AIR abstractions: frames, constraints, execution trace
    poly/       Univariate polynomial helpers
    hash.zig    M31/CM31/QM31 field-element hashing
    fri.zig     FRI low-degree test (folding, remainder, queries)
    stark.zig   DEEP-FRI STARK prover / verifier + Fibonacci AIR
  binius/       Binary-field (Binius/BSV) stack over GF(2^k)
    tower.zig   Canonical Wiedemann tower: Gf2 .. Gf2_128
    field.zig   BinaryField GF(2^k) arithmetic
    sumcheck.zig    Sum-check over binary fields
    polynomial.zig  Multilinear polynomials, univariate interpolation
    pcs.zig     Merkle-bound committed multilinear PCS
    fripcs.zig  Polylog FRI-Binius PCS (FRI fold in lockstep with the eval sum-check)
    batchpcs.zig Batched eval PCS (one shared Merkle tree per FRI layer across columns)
    stark.zig   Zero-check STARK prover / verifier
    adder.zig   Bit-sliced ripple-carry adder gadget
    bitpack.zig Bit-pack gadget (boolean bit columns + packed value)
    rangecheck.zig Range-check gadget (value fits in 2^m)
    compare.zig Bit-sliced less-than / equality comparison gadget
    constraints.zig Comptime constraint DSL for composing gadgets
    addfri.zig  Additive FRI low-degree test over the tower field
    arg.zig     Argument composition (sum-check + committed PCS)
  cuda/         Experimental CUDA Driver API bindings + PTX kernels (src/cuda)
examples/
  fibonacci/    STARK proving a Fibonacci sequence
  rescue/       STARK proving a Rescue permutation
  ml_linear/    STARK proving a linear layer y = w . x
  binius_adder/ Binius STARK proving a batch of 4-bit additions
  binius_bitpack/ Binius STARK proving a batch of 8-bit values
  binius_rangecmp/ Binius STARK proving a bounded strictly-increasing sequence
tests/          End-to-end tests
benchmarks/     NTT / circle-FFT / Binius-STARK benchmarks (zig build bench[-binius])
bindings/       C ABI (zig-capi.h) + JS/WebAssembly binding (bindings/js) + Node N-API addon (bindings/node)
```

Modules are exported via `src/root.zig` (`core`, `m31`, `binius` namespaces), so library consumers can depend on the field-agnostic primitives without pulling in the M31 tower.

## Building

Requires Zig 0.16.0 (stable). The exact toolchain is pinned in CI
(`.github/workflows/ci.yml`) and in the `Dockerfile` (SHA-256 verified); a
reproducible shell is `docker run --rm zig-stark zig build test`.

```sh
zig build            # build examples
zig build test       # run unit and e2e tests
zig build fmt        # check formatting
zig build bench      # run NTT benchmarks (-Doptimize=ReleaseFast recommended)
zig build bench-binius # run Binius STARK benchmarks (-Doptimize=ReleaseFast recommended)
zig build wasm       # build the C ABI as a wasm32 module (bindings/js)
zig build fuzz       # randomized gadget fuzz (prove/verify/tamper)
zig build node-addon -Dnapi-include=<node/include/dir> # Node.js N-API addon (bindings/node)
zig build cuda-hello # CUDA validation kernel (requires GPU + driver); kernels: zig build cuda-kernels
zig build cuda-gf     # Gf256 field-mul kernel: bit-exactness vs the CPU tower
zig build cuda-sumcheck # Gf256 sum-check round on the GPU: bit-exact + full Stark proof compare
```

Run the examples:

```sh
./zig-out/bin/fibonacci
./zig-out/bin/rescue
./zig-out/bin/ml_linear
./zig-out/bin/binius_adder
./zig-out/bin/binius_bitpack
./zig-out/bin/binius_rangecmp
```

## Fields

- `M31` — the prime field modulo `2^31 - 1` (Mersenne). Scalar and SIMD (`Vec8`) operations: `add`, `sub`, `mul`, `neg`, `inv`, `pow`, `primitiveRootOfUnity`.
- `CM31` — quadratic extension of M31 (`M31[i]`).
- `QM31` — quartic extension (tower `M31 -> CM31 -> QM31`), the "secure" field carrying the full 2^32-th roots of unity used for FRI and STARK arithmetic.
- `Gf16` / `Gf256` — `BinaryField` over GF(2^4) / GF(2^8) (`src/binius/field.zig`), small script-friendly witness fields.
- `tower.Gf2 .. Gf2_128` — the canonical Wiedemann tower of binary fields (`src/binius/tower.zig`); `Gf2_128 = TowerField(7)` is the usual soundness extension field `E` (≈ 2^-128 Schwartz-Zippel error) for a small base `F`.

## Benchmarks

Numbers below are wall-clock on an **AMD Ryzen 7 5800H** (Linux x86_64), Zig
0.16.0 stable, `-Doptimize=ReleaseFast`, single-threaded, from
`zig build bench` and `zig build bench-binius`. Run them yourself with
`zig build bench -Doptimize=ReleaseFast` / `zig build bench-binius
-Doptimize=ReleaseFast`.

**Circle FFT** (times in ns per transform over M31):

```
lg    n        fft       ifft    naive   speedup
 8   256      89069     114042   488361   5.5x
10  1024     314060     378928  6174127  19.7x
12  4096    1308518    1507427        -       -
14 16384    5056218    5801445        -       -
16 65536   21785973   24592493        -       -
```

**Binius zero-check STARK** — a batch of 4-bit additions (16 columns, 16
constraints), `F = Gf256`, soundness extension `E = Gf2_128`, eval-openings
(`CommittedMlePcs`):

```
   k      n   prove_ms  verify_ms  sumcheck_B  eval_open_B   total_KB
   3      8       6.15       0.73         288        12416       12.4
   5     32      45.71       3.32         640        82432       81.1
   7    128     275.67      16.87        1120       460800      451.1
   9    512    1610.21      84.32        1728      2367488     2313.7
  11   2048    8751.21     404.21        2464     11567104    11298.4
```

The eval-open section grows O(2^k·k) (it opens every hypercube entry per
column); the polylog FRI-Binius PCS (`BiniusStarkFri`) replaces it with an
O(polylog) proof (see the k = 4..6 proof-size e2e test).

**Parallel prover** (`Stark.proveParallel`): the per-column commitments, the
combined zero-check sum-check rounds, and the per-column eval openings run
across a worker pool (`core.pool.Pool`, `zig build bench-binius`):

```
parallel prove scaling (4-bit adder, k=7, extension Gf2_128):
  threads     prove_ms  speedup
        1       287.80    1.00x
        2       166.26     1.73x
        4        96.67     2.98x
        8        72.47     3.97x
       16        77.81     3.70x
```

8 cores saturate (the 5800H has 8 physical cores); the remaining sequential
transcript/interpolation work caps further gains. The allocator used with
`proveParallel` must be thread-safe (e.g. `std.heap.DebugAllocator` or
`std.heap.smp_allocator`).

## Releases

See [`CHANGELOG.md`](CHANGELOG.md) for per-version changes. Released versions
are tagged `vX.Y.Z`; the public API follows semantic versioning, so 0.x minor
bumps may break the API and are documented in the changelog.

## License

Copyright 2026 Tomás Díaz. Licensed under the [Apache License, Version 2.0](LICENSE).
