# zig-stark

A STARK (Scalable Transparent Argument of Knowledge) proof system implemented in Zig, proving the correct execution of AIR state machines over the M31 / CM31 / QM31 field tower with Merkle commitments and a DEEP-FRI low-degree test.

## Status

Working end-to-end DEEP-FRI STARK. The prover and verifier in `src/m31/stark.zig` handle any AIR implementing the `GenericStark` interface — including optional preprocessed columns and **LogUp multiset lookups** — and ship with three complete examples: a Fibonacci sequence, a Rescue permutation, and a single linear ML layer. 80 tests pass (77 unit + 3 end-to-end) with no leaks.

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
  binius/       Binary-field (Binius/BSV) stack (GF(2^k) zero-check sum-check)
examples/
  fibonacci/    STARK proving a Fibonacci sequence
  rescue/       STARK proving a Rescue permutation
  ml_linear/    STARK proving a linear layer y = w . x
tests/          End-to-end tests
benchmarks/     NTT / circle-FFT benchmarks (zig build bench)
```

Modules are exported via `src/root.zig` (`core`, `m31`, `binius` namespaces), so library consumers can depend on the field-agnostic primitives without pulling in the M31 tower.

## Building

Requires Zig 0.16.x.

```sh
zig build            # build examples
zig build test       # run unit and e2e tests
zig build bench      # run NTT benchmarks (-Doptimize=ReleaseFast recommended)
```

Run the examples:

```sh
./zig-out/bin/fibonacci
./zig-out/bin/rescue
./zig-out/bin/ml_linear
```

## Fields

- `M31` — the prime field modulo `2^31 - 1` (Mersenne). Scalar and SIMD (`Vec8`) operations: `add`, `sub`, `mul`, `neg`, `inv`, `pow`, `primitiveRootOfUnity`.
- `CM31` — quadratic extension of M31 (`M31[i]`).
- `QM31` — quartic extension (tower `M31 -> CM31 -> QM31`), the "secure" field carrying the full 2^32-th roots of unity used for FRI and STARK arithmetic.

## License

See `build.zig.zon` for module metadata. See `TODO.md` for the roadmap.
