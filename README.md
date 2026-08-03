# zig-stark

A STARK (Scalable Transparent Argument of Knowledge) proof system implemented in Zig, proving the correct execution of AIR state machines over the M31 / CM31 / QM31 field tower with Merkle commitments and a DEEP-FRI low-degree test.

## Status

Working end-to-end DEEP-FRI STARK. The prover and verifier in `src/stark/` handle any AIR implementing the `GenericStark` interface, and ship with two complete examples: a Fibonacci sequence and a single linear ML layer. 64 unit tests pass with no leaks.

## Documentation

- [`docs/overview.md`](docs/overview.md) — architecture, field tower, module layout, build/test/run instructions
- [`docs/protocol.md`](docs/protocol.md) — the full DEEP-FRI protocol: composition, quotient, DEEP combination, FRI, and the exact transcript order
- [`docs/examples.md`](docs/examples.md) — how the Fibonacci and linear-ML examples work, and how to write a new AIR

## Project structure

```
src/
  field/        M31, CM31, QM31 field arithmetic + SIMD helpers
  circle/       Circle point group, domains, cosets
  ntt/          Classic NTT, SIMD butterflies, naive circle FFT
  air/          AIR abstractions: frames, constraints, execution trace
  poly/         Univariate polynomial helpers
  hash/         Blake3 hash + field-element hashing
  merkle/       Merkle tree commit / open / verify
  channel/      Fiat-Shamir transcript
  fri/          FRI low-degree test (folding, remainder, queries)
  stark/        DEEP-FRI STARK prover / verifier + Fibonacci AIR
  utils/        Bit manipulation and SIMD utilities
examples/
  fibonacci/    STARK proving a Fibonacci sequence
  rescue/       Rescue hash STARK example (TODO)
  ml_linear/    STARK proving a linear layer y = w . x
tests/          End-to-end tests
```

## Building

Requires Zig 0.16.x.

```sh
zig build            # build examples
zig build test       # run unit and e2e tests
```

Run the examples:

```sh
./zig-out/bin/fibonacci
./zig-out/bin/ml_linear
```

## Fields

- `M31` — the prime field modulo `2^31 - 1` (Mersenne). Scalar and SIMD (`Vec8`) operations: `add`, `sub`, `mul`, `neg`, `inv`, `pow`, `primitiveRootOfUnity`.
- `CM31` — quadratic extension of M31 (`M31[i]`).
- `QM31` — quartic extension (tower `M31 -> CM31 -> QM31`), the "secure" field carrying the full 2^32-th roots of unity used for FRI and STARK arithmetic.

## License

See `build.zig.zon` for module metadata. See `TODO.md` for the roadmap.
