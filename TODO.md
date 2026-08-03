# TODO

## Field arithmetic
- [ ] Add unit tests for M31 arithmetic (add/sub/mul/neg/inv/pow, edge cases at modulus boundaries).
- [ ] Add unit tests for CM31 and QM31 arithmetic and extension-tower identities.
- [ ] Verify M31 generator and two-adic root values against reference implementations.
- [ ] Replace scalar-scalar looped SIMD (`Vec8`) with true vectorized arithmetic (no scalar reduction loop).
- [ ] Add `toBytes`/`fromBytes` serialization for M31, CM31, QM31.

## Circle geometry
- [ ] Add tests for circle point group properties (closure, identity, inverse, `onCircle`).
- [ ] Add tests for `CircleDomain` and `CircleCoset` (size, `get`/`at`, `half`).
- [ ] Implement faster scalar multiplication (windowed / precomputed tables) for domain generation.
- [ ] Verify generator coordinates `(1268011823, 2)` against references.

## NTT
- [ ] Add round-trip test: `nttForward` then `nttInverse` returns the original vector.
- [ ] Add SIMD NTT correctness tests (compare against `nttClassic`).
- [ ] Replace naive circle FFT with recursive fold algorithm (O(n log n)).
- [ ] Replace naive Lagrange circle IFFT with optimized inverse transform.
- [ ] Support arbitrary coset evaluation (eval on `CircleCoset`).

## AIR
- [x] Define the full `Air` interface: columns, transition constraints, boundary assertions.
- [x] Implement constraint composition and quotienting.
- [x] Add `poly/` helpers: univariate/bivariate polynomial structs, interpolation, vanishing polynomials.

## Polynomial commitment stack
- [x] `hash/`: implement a secure hash (e.g. Blake3/Keccak wrapper or Rescue for STARK-friendly use).
- [x] `merkle/`: Merkle tree commit/open/verify with M31 hashing.
- [x] `channel/`: proof transcript (transcript-fiat-shamir) feeding the hash.
- [x] `fri/`: FRI commitment over QM31 (or circle FRI), folding, queries.
- [x] `stark/`: prover and verifier pipelines tying AIR + FRI + Merkle together.

## Examples
- [x] `fibonacci`: executable STARK proof for a Fibonacci AIR.
- [x] `ml_linear`: STARK for a linear ML (matrix-vector) computation.
- [ ] `rescue`: STARK proving a Rescue permutation.
- [ ] `rescue`: STARK proving a Rescue permutation.
- [ ] `ml_linear`: STARK for a linear ML (matrix-vector) computation.

## Testing / build
- [ ] Add benchmark for NTT at various sizes.
- [ ] Add prover/verifier e2e tests once `stark/` lands.
- [ ] Add `zig fmt` formatting check / CI configuration.
