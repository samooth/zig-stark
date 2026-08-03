# zig-stark

A STARK (Scalable Transparent Argument of Knowledge) proof system implemented in Zig, with support for the M31 field and circle-domain constructions.

## Status

Early-stage implementation. Field arithmetic, circle geometry, NTT, and AIR abstractions are in place. Merkle tree, FRI, channel, hashing, and the prover/verifier pipeline are not yet implemented.

## Project structure

```
src/
  field/        M31, CM31, QM31 field arithmetic + SIMD helpers
  circle/       Circle point group, domains, cosets
  ntt/          Classic NTT, SIMD butterflies, naive circle FFT
  air/          AIR abstractions: frames, constraints, execution trace
  utils/        Bit manipulation and SIMD utilities
  poly/         (empty - polynomial helpers)
  merkle/       (empty - Merkle tree commitment)
  channel/      (empty - proof transcript)
  hash/         (empty - hash function)
  fri/          (empty - FRI commitment)
  stark/        (empty - prover/verifier)
examples/
  fibonacci/    Fibonacci STARK example (stub)
  rescue/       Rescue hash STARK example (stub)
  ml_linear/    Linear ML STARK example (stub)
tests/          End-to-end tests
```

## Building

Requires Zig 0.14.0 or later.

```sh
zig build            # build examples
zig build test       # run unit and e2e tests
```

## Fields

- `M31` — the prime field modulo `2^31 - 1` (Montgomery-friendly). Scalar and SIMD (`Vec8`) operations: `add`, `sub`, `mul`, `neg`, `inv`, `pow`, `primitiveRootOfUnity`.
- `CM31` — quadratic extension of M31 (`M31[i]`), used for FRI.
- `QM31` — quartic extension (tower: `M31 -> CM31 -> QM31`), the "secure" field used in the polynomial commitment.

## License

See `build.zig.zon` for module metadata. See `TODO.md` for the roadmap.
