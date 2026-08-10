# zig-stark

A STARK (Scalable Transparent Argument of Knowledge) proof system implemented in Zig, with two stacks: a DEEP-FRI STARK over the M31 / CM31 / QM31 field tower (Mersenne prime fields), and a Binius/BSV-style binary-field stack over the canonical tower of GF(2^k) using zero-check constraints enforced by sum-check with Merkle-committed multilinear polynomials.

## Status

Working end-to-end on both stacks:

- **M31 DEEP-FRI STARK** — the prover and verifier in `src/m31/stark.zig` handle any AIR implementing the `GenericStark` interface, including optional preprocessed columns and **LogUp multiset lookups**, with three complete examples: a Fibonacci sequence, a Rescue permutation, and a single linear ML layer.
- **Binius binary-field stack** — a zero-check STARK (`src/binius/stark.zig`) over the canonical Wiedemann tower of binary fields (`src/binius/tower.zig`), combining committed multilinear PCS openings via sum-check (`src/binius/sumcheck.zig`, `src/binius/pcs.zig`), with an additive FRI low-degree test (`src/binius/addfri.zig`) and a batched 4-bit ripple-carry adder gadget (`src/binius/adder.zig`) demonstrated by an end-to-end example.

148 tests pass (143 unit + 5 end-to-end) with no leaks.

## Documentation

- [`docs/overview.md`](docs/overview.md) — architecture, field tower, module layout, build/test/run instructions
- [`docs/protocol.md`](docs/protocol.md) — the full DEEP-FRI protocol: composition, quotient, DEEP combination, FRI, and the exact transcript order
- [`docs/examples.md`](docs/examples.md) — how the Fibonacci and linear-ML examples work, and how to write a new AIR

## Project structure

```
src/
  core/         Field-agnostic primitives: hash (Blake3), merkle, channel, simd
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
    stark.zig   Zero-check STARK prover / verifier
    adder.zig   Bit-sliced ripple-carry adder gadget
    addfri.zig  Additive FRI low-degree test over the tower field
    arg.zig     Argument composition (sum-check + committed PCS)
examples/
  fibonacci/    STARK proving a Fibonacci sequence
  rescue/       STARK proving a Rescue permutation
  ml_linear/    STARK proving a linear layer y = w . x
  binius_adder/ Binius STARK proving a batch of 4-bit additions
tests/          End-to-end tests
benchmarks/     NTT / circle-FFT / Binius-STARK benchmarks (zig build bench[-binius])
```

Modules are exported via `src/root.zig` (`core`, `m31`, `binius` namespaces), so library consumers can depend on the field-agnostic primitives without pulling in the M31 tower.

## Building

Requires Zig 0.16.x.

```sh
zig build            # build examples
zig build test       # run unit and e2e tests
zig build bench      # run NTT benchmarks (-Doptimize=ReleaseFast recommended)
zig build bench-binius # run Binius STARK benchmarks (-Doptimize=ReleaseFast recommended)
```

Run the examples:

```sh
./zig-out/bin/fibonacci
./zig-out/bin/rescue
./zig-out/bin/ml_linear
./zig-out/bin/binius_adder
```

## Fields

- `M31` — the prime field modulo `2^31 - 1` (Mersenne). Scalar and SIMD (`Vec8`) operations: `add`, `sub`, `mul`, `neg`, `inv`, `pow`, `primitiveRootOfUnity`.
- `CM31` — quadratic extension of M31 (`M31[i]`).
- `QM31` — quartic extension (tower `M31 -> CM31 -> QM31`), the "secure" field carrying the full 2^32-th roots of unity used for FRI and STARK arithmetic.

## License

See `build.zig.zon` for module metadata. See `TODO.md` for the roadmap.
