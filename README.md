# zig-stark

A STARK (Scalable Transparent Argument of Knowledge) proof system implemented in Zig, with two stacks: a DEEP-FRI STARK over the M31 / CM31 / QM31 field tower (Mersenne prime fields), and a Binius/BSV-style binary-field stack over the canonical tower of GF(2^k) using zero-check constraints enforced by sum-check with Merkle-committed multilinear polynomials.

## Status

Working end-to-end on both stacks:

- **M31 DEEP-FRI STARK** — the prover and verifier in `src/m31/stark.zig` handle any AIR implementing the `GenericStark` interface, including optional preprocessed columns and **LogUp multiset lookups**, with three complete examples: a Fibonacci sequence, a Rescue permutation, and a single linear ML layer.
- **Binius binary-field stack** — a zero-check STARK (`src/binius/stark.zig`) over the canonical Wiedemann tower of binary fields (`src/binius/tower.zig`), combining committed multilinear PCS openings via sum-check (`src/binius/sumcheck.zig`, `src/binius/pcs.zig`), with an additive FRI low-degree test (`src/binius/addfri.zig`), a standalone product-sum argument (`src/binius/arg.zig`, now `(F, E, PCS)`-parameterized like the STARK), a batched 4-bit ripple-carry adder gadget (`src/binius/adder.zig`), and a bit-pack gadget (`src/binius/bitpack.zig`), each demonstrated by an end-to-end example. The STARK is parameterized over field, extension field, and the committed-MLE PCS (`CommittedMlePcs` opens all 2^k entries; the `PackedPcs` mode in `src/binius/packed_pcs.zig` commits each witness column as a *packed* univariate polynomial via a column-Merkle tree, opening only the row combination and a handful of sampled columns for sub-linear proofs). The **polylog FRI-Binius PCS** (`src/binius/fripcs.zig`, wired in as `BiniusStarkFri` / `BiniusArgFri`) FRI-folds the additive-NTT code in lockstep with the eval sum-check for O(polylog) proof size. It supports boundary pins (public column-point evaluations folded into the zero-check, like M31 boundary assertions), and all randomness flows through a single unified Fiat-Shamir channel (`src/core/channel/channel.zig`) that also binds public inputs. The protocol can run over a large extension field `E` (e.g. `tower.Gf2_128`) of a small witness field `F`, keeping ≈ 2^-128 Schwartz-Zippel soundness for script-friendly GF(16)/GF(256) witnesses at the price of `E`-field arithmetic.

196 tests pass (187 unit + 9 end-to-end) with no leaks.

## Documentation

- [`docs/overview.md`](docs/overview.md) — architecture, field tower, module layout, build/test/run instructions
- [`docs/protocol.md`](docs/protocol.md) — the full DEEP-FRI protocol: composition, quotient, DEEP combination, FRI, and the exact transcript order
- [`docs/examples.md`](docs/examples.md) — how the Fibonacci and linear-ML examples work, and how to write a new AIR
- [`docs/binius.md`](docs/binius.md) — the binary-field stack's soundness: transcript order, every Schwartz-Zippel error term, concrete `(Gf256, Gf2_128)` security, the FRI final-check and packing identities

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
    fripcs.zig  Polylog FRI-Binius PCS (FRI fold in lockstep with the eval sum-check)
    stark.zig   Zero-check STARK prover / verifier
    adder.zig   Bit-sliced ripple-carry adder gadget
    bitpack.zig Bit-pack gadget (boolean bit columns + packed value)
    addfri.zig  Additive FRI low-degree test over the tower field
    arg.zig     Argument composition (sum-check + committed PCS)
examples/
  fibonacci/    STARK proving a Fibonacci sequence
  rescue/       STARK proving a Rescue permutation
  ml_linear/    STARK proving a linear layer y = w . x
  binius_adder/ Binius STARK proving a batch of 4-bit additions
  binius_bitpack/ Binius STARK proving a batch of 8-bit values
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
./zig-out/bin/binius_bitpack
```

## Fields

- `M31` — the prime field modulo `2^31 - 1` (Mersenne). Scalar and SIMD (`Vec8`) operations: `add`, `sub`, `mul`, `neg`, `inv`, `pow`, `primitiveRootOfUnity`.
- `CM31` — quadratic extension of M31 (`M31[i]`).
- `QM31` — quartic extension (tower `M31 -> CM31 -> QM31`), the "secure" field carrying the full 2^32-th roots of unity used for FRI and STARK arithmetic.
- `Gf16` / `Gf256` — `BinaryField` over GF(2^4) / GF(2^8) (`src/binius/field.zig`), small script-friendly witness fields.
- `tower.Gf2 .. Gf2_128` — the canonical Wiedemann tower of binary fields (`src/binius/tower.zig`); `Gf2_128 = TowerField(7)` is the usual soundness extension field `E` (≈ 2^-128 Schwartz-Zippel error) for a small base `F`.

## Releases

See [`CHANGELOG.md`](CHANGELOG.md) for per-version changes. Released versions
are tagged `vX.Y.Z`; the public API follows semantic versioning, so 0.x minor
bumps may break the API and are documented in the changelog.

## License

See `build.zig.zon` for module metadata. See `TODO.md` for the roadmap.
