# zig-stark: Overview

`zig-stark` is a STARK (Scalable Transparent Argument of Knowledge) proof system
implemented in Zig. It proves the correct execution of a state machine (an
*Algebraic Intermediate Representation*, AIR) using the M31 / CM31 / QM31 field
tower, a Merkle commitment scheme, and a FRI low-degree test composed via the
DEEP method.

The current implementation is a complete **DEEP-FRI STARK**: prover and verifier
for any AIR that fits the `GenericStark` interface, with end-to-end proofs for a
Fibonacci sequence, a Rescue permutation, and a single linear ML layer. AIRs may
optionally add preprocessed (lookup table) columns checked with a **LogUp
multiset argument** (e.g. range checks), committed in a second protocol phase.

There is also a complete **Binius / BSV binary-field stack** (`binius`): a
zero-check STARK over a tower field with a pluggable committed-MLE PCS, a
gadget library (bit-sliced adder, bit-pack, range check, comparison) with a
comptime constraint DSL for composing gadgets, proof serialization, and
end-to-end examples (`binius_adder`, `binius_bitpack`, `binius_rangecmp`).

## Field tower

| Field | Construction | Role |
|-------|--------------|------|
| `M31` | `F_(2^31 - 1)`, the Mersenne prime field | Native values; fast 32-bit modular arithmetic |
| `CM31` | `M31[i]`, `i^2 = -1` | Quadratic extension |
| `QM31` | `CM31[v]` (tower `M31 -> CM31 -> QM31`) | The "secure" field: FRI, polynomial commitments, and STARK arithmetic |

`QM31` contains the full 2^32-th roots of unity, which is what allows the
radix-2 evaluation domains (subgroups) used by FRI and the STARK. `M31`
itself has 2-adicity 1 and is therefore only used for native arithmetic.

## Module layout

The source tree is split into three modules, re-exported by `src/root.zig`:

- `core` — field-agnostic primitives: Blake3 hashing, Merkle trees, the
  Fiat-Shamir transcript channel, canonical proof serialization, SIMD/bit
  utilities.
- `m31` — the M31/CM31/QM31 STARK stack: field tower, circle geometry, NTTs,
  AIR abstractions, univariate polynomials, FRI, and the DEEP-FRI STARK.
  Field-element hashing lives here (`src/m31/hash.zig`).
- `binius` — binary-field (Binius/BSV) stack over GF(2^k): zero-check constraints,
  combined sum-check, Fiat-Shamir binding, pluggable committed-MLE
  evaluation proofs (`CommittedMlePcs`, sub-linear `PackedPcs` and polylog
  `FriPcs` / batched `BatchFriPcs`), and a gadget library (adder, bit-pack,
  range check, comparison) composable through a comptime constraint DSL.

```
src/
  root.zig      Module namespaces (core, m31, binius)
  core/         Field-agnostic: hash, merkle, channel, serialization, pool, bit_utils, simd
  m31/
    field/      M31, CM31, QM31 arithmetic (+ SIMD helpers)
    circle/     Circle point group, domains, cosets
    ntt/        Classic NTT, SIMD butterflies, circle FFT (recursive fold)
    air/        AIR abstractions: frames, constraints, execution trace
    poly/       Univariate polynomials: eval, add/mul, interpolation, vanishing poly
    hash.zig    M31/CM31/QM31 field-element hashing
    fri.zig     FRI low-degree test (commit, fold, queries)
    stark.zig   DEEP-FRI STARK prover / verifier (incl. LogUp lookups) + test AIRs
  binius/       Binary-field stack (GF(2^k) zero-check sum-check)
    tower.zig   Canonical Wiedemann tower: Gf2 .. Gf2_128
    field.zig   BinaryField GF(2^k) arithmetic
    sumcheck.zig    Sum-check over binary fields
    polynomial.zig  Multilinear polynomials, univariate interpolation
    pack.zig    Packed-MLE interpolation / novel-basis evaluation (novelEval)
    pcs.zig     Merkle-bound committed multilinear PCS (O(2^k) openings)
    packed_pcs.zig  Sub-linear PCS via row packing (additive NTT) + column Merkle tree
    fripcs.zig  Polylog FRI-Binius PCS (FRI fold in lockstep with the eval sum-check)
    batchpcs.zig Batched eval PCS (one shared Merkle tree per FRI layer across columns)
    stark.zig   Zero-check STARK prover / verifier (pluggable PCS)
    adder.zig   Bit-sliced ripple-carry adder gadget
    bitpack.zig Bit-pack gadget (boolean bit columns + packed value)
    rangecheck.zig Range-check gadget (value fits in 2^m)
    compare.zig Bit-sliced less-than / equality comparison gadget
    constraints.zig Comptime constraint DSL for composing gadgets
    addfri.zig  Additive FRI low-degree test over the tower field
    arg.zig     Argument composition (sum-check + committed PCS)
    capi.zig    C ABI for the Binius STARK (host allocator, wire-format I/O)
examples/
  fibonacci/    STARK proving a Fibonacci sequence
  rescue/       STARK proving a Rescue permutation (degree-5 sbox)
  ml_linear/    STARK proving a single linear layer y = w . x
  binius_adder/ Binius STARK proving a batch of 4-bit additions
  binius_bitpack/ Binius STARK proving a batch of 8-bit values
  binius_rangecmp/ Binius STARK proving a bounded strictly-increasing sequence
bindings/
  js/             WebAssembly binding (ESM/CJS/TS wrapper + .wasm)
  node/           Node.js N-API native addon
tests/          Library and end-to-end tests
docs/           This documentation
```

## Building and testing

Requires Zig 0.16.x.

```sh
zig build            # builds the example executables
zig build test       # runs the library unit tests and e2e tests
zig test src/root.zig # equivalent unit-test entry point
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

All six prove a statement, verify it, and reject a forged claim.

## Soundness of the committed protocol

The protocol is described in detail in [`protocol.md`](protocol.md), with a
consumer-facing API reference and library-integration guide in
[`api.md`](api.md). Three
soundness-relevant properties of this implementation deserve emphasis:

1. **The FRI remainder is a proper code.** The final folded layer is a codeword
   of degree `< 2^(remainder_log - log_blowup)` on `2^remainder_log` points,
   and is interpolated from a strict subset of those points. This makes the
   verifier's "final codeword is low-degree" check real: a commitment to a
   non-low-degree codeword is rejected with overwhelming probability.

2. **The verifier checks the DEEP identity and the constraint identity at every
   query.** The committed FRI codeword (the DEEP combination `g`) must agree
   with the revealed trace/quotient values, and the composition must satisfy
   `Hc(x) = Z_H(x) * Q(x)`, catching both wrong boundary claims and tampered
   reveals.

3. **Lookup claims are enforced by cyclic LogUp constraints.** Each lookup
   relation contributes an accumulator column plus a denominator-cleared
   transition constraint that holds on *every* row of `H` (no
   `(x - w^(n-1))` factor), so a multiset mismatch cannot hide behind the
   exempted last row. The accumulator is committed only after the lookup
   challenges are sampled, so a malicious prover cannot tailor it to `alpha`.

See [`protocol.md`](protocol.md) for the full transcript order and the exact
algebraic identities.

## Binius extension-field soundness

The binary-field stack (`binius`) lets the protocol run over an extension field
`E` of the witness field `F` (`BiniusStark(F, E)`, `MlePcs(F, E)`;
take `E = F` for the classic single-field setting). The PCS is a parameter of
the STARK (`BiniusStarkWith`, plus the `BiniusStarkFri` convenience for the
polylog FRI-Binius PCS): `CommittedMlePcs(F, E)` opens every hypercube entry,
while `PackedPcs` (row packing + column Merkle tree) and `FriPcs` (FRI fold in
lockstep with the eval sum-check, O(polylog) proofs) are sub-linear. The
witness columns, the Merkle-committed tables, and the leaves stay in `F`,
while the zero-check point τ, the combination coefficients α_t, the sum-check
round challenges, and the PCS query points are sampled in `E`. Base-field
entries enter the sum-check by the zero-cost tower embedding (identical bit
string, `tower.TowerField.embed`), so the prover never re-commits.

Why run the protocol in `E` at all? The evaluation sum-check composes the
multilinear factors and sum-checks their degree-`d` product; a cheating prover
is caught only by the Schwartz-Zippel randomness in τ, α_t, and the round
challenges. In the single-field setting the soundness error is therefore
≈ `1/|F|` per application — negligible for a 128-bit field, but only `1/16`
(GF(16)) or `1/256` (GF(256)) when `F` is a small script-friendly field. Lifting
the protocol to a large extension `E` (e.g. `tower.Gf2_128` = GF(2^128)) turns
every `1/|F|` into `1/|E|`, keeping ≈ `2^-128` soundness while the witness stays
tiny. The price is that all round arithmetic (the prover's dominant cost) runs
in `E`, e.g. GF(2^128) instead of GF(256).
