# zig-stark: Overview

`zig-stark` is a STARK (Scalable Transparent Argument of Knowledge) proof system
implemented in Zig. It proves the correct execution of a state machine (an
*Algebraic Intermediate Representation*, AIR) using the M31 / CM31 / QM31 field
tower, a Merkle commitment scheme, and a FRI low-degree test composed via the
DEEP method.

The current implementation is a complete **DEEP-FRI STARK**: prover and verifier
for any AIR that fits the `GenericStark` interface, with end-to-end proofs for a
Fibonacci sequence and for a single linear ML layer. AIRs may optionally add
preprocessed (lookup table) columns checked with a **LogUp multiset argument**
(e.g. range checks), committed in a second protocol phase.

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

```
src/
  field/        M31, CM31, QM31 arithmetic (+ SIMD helpers)
  circle/       Circle point group, domains, cosets
  ntt/          Classic NTT, SIMD butterflies, naive circle FFT
  air/          AIR abstractions: frames, constraints, execution trace
  poly/         Univariate polynomials: eval, add/mul, interpolation, vanishing poly
  hash/         Blake3 wrapper + field-element hashing
  merkle/       Merkle tree commit / open / verify
  channel/      Fiat-Shamir transcript (absorb / sample)
  fri/          FRI low-degree test (commit, fold, queries)
  stark/        DEEP-FRI STARK prover / verifier (incl. LogUp lookups) + test AIRs
  utils/        Bit manipulation and SIMD utilities
examples/
  fibonacci/    STARK proving a Fibonacci sequence
  rescue/       STARK proving a Rescue permutation (degree-5 sbox)
  ml_linear/    STARK proving a single linear layer y = w . x
tests/          Library and end-to-end tests
docs/           This documentation
```

## Building and testing

Requires Zig 0.16.x.

```sh
zig build            # builds the three example executables
zig build test       # runs the library unit tests and e2e tests
zig test src/lib.zig # equivalent unit-test entry point
```

Run the examples:

```sh
./zig-out/bin/fibonacci
./zig-out/bin/rescue
./zig-out/bin/ml_linear
```

All three prove a statement, verify it, and reject a forged claim.

## Soundness of the committed protocol

The protocol is described in detail in [`protocol.md`](protocol.md). Three
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
