# TODO — Binius stack (binary-field / BSV)

Current status: zero-check STARK over the tower field with committed-MLE PCS
(`CommittedMlePcs` opens every hypercube entry, O(2^k) proof size), an
extension-field `(F, E)` soundness mode, boundary pins, additive FRI
(`addfri.zig`, standalone/unused), and a batched 4-bit adder gadget. 158 tests.

## 1. Sub-linear MLE evaluation / commitment (HIGH, in progress)

`CommittedMlePcs` proves `y = f(r)` by an eval sum-check + a Merkle opening of
all 2^k entries. Goal: sub-linear (O(polylog) or O(2^(k/2))) openings by
committing the *packed* MLE as a univariate polynomial and FRI-ing it.

### Worked-out foundation (math is settled, code in `src/binius/pack.zig`)

- **Packing.** Let H = {`fromInt(i)` : i < 2^k} ⊂ F be the low-bits additive
  subgroup, Z_H(x) = ∏_{y∈H}(x + y) its vanishing poly (a linearized poly of
  degree N = 2^k, built by successively adjoining basis vectors; note
  Z_H(x) = x^(2^k) + x only when H is a subfield, i.e. k an index of the
  tower). The packed polynomial g is the unique interpolation of the MLE table
  on H: g(x_i) = f(i). Lagrange basis L_i(x) = Z_H(x)/(x + x_i) / d with
  d = Z_H'(x) = ∏_{z∈H∖{0}} z constant over H (d = 1 iff H is a subfield), so
  g = Σ_i f(i)·L_i.
- **Evaluation identity (coefficient extraction).** For the kernel
  β_r(x) = ∏_j (x_j + 1 + r_j) and B_r = interpolation of y ↦ β_r(bits(y)) on H,
      f(r) = Σ_{x∈H} f(x)·β_r(x) = d · [x^(N-1)] ( g·B_r  mod Z_H ),   N = 2^k
  (verified numerically for all k ≤ BITS incl. non-subfield k: each L_i has
  leading coeff 1/d, so the leading coefficient of g·B_r mod Z_H is f(r)/d).
- `pack.interpolate(table) -> g`, `pack.eval(g, r) -> f(r)` are implemented and
  tested against direct MLE eval. O(N^2) for now (N = 2^k); swap in an additive
  FFT (Gao–Mateer) when k grows.

### Remaining protocol steps

1. FRI-commit g (`AdditiveFri`, log_size = k). Layer-0 codeword points are
   `fromInt(j)`, j < 2^(k+blowup); the first 2^k indices ARE the table, so the
   commitment pins f's values directly.
2. Sound sub-linear eval. NOTE (from analysis): the naive "reveal the partial
   row-sum polynomial h and sample rows for consistency" is NOT sound — a
   deviation d(y) supported on one row passes row sampling with prob
   ~1 - q/2^(k1) and lets the prover steer the final sum. Do NOT use it.
   Required: a Schwartz-Zippel-sound consistency check. Two correct routes:
   - Binius paper §4 style: fold the MLE eval onto the univariate g via the
     trace/coefficient-extraction and check it with FRI queries + the additive
     FFT structure (polylog proof, the real target).
   - Simpler sound fallback: split k = k1 + k2, FRI-commit g, have the verifier
     recompute f(r) = Σ_y β(y)·h(y) from a *committed* h, and run an eval
     sum-check that ends in f(r') where f(r') itself is obtained via the packed
     route — chain of two, still needs a sound h↔g binding.
3. Wire into the STARK — DONE: `BiniusStarkWith(F, E, max_cols, Pcs)` in
   `stark.zig` makes the committed-MLE PCS a parameter; `PackedPcsStark`
   (`src/binius/packed_pcs.zig`) adapts `PackedPcs` to that interface (k1 = k -
   k2, RS domain capped by `F.BITS`), and `BiniusStark` still defaults to
   `CommittedMlePcs` as the O(2^k) test oracle. End-to-end packed-mode tests
   cover Gf16, Gf256 (k=6), and (F=Gf16, E=Gf2^128).
4. Extension-field support (eval point r ∈ E): FRI currently runs over the base
   tower field F; the packed protocol must evaluate g at E-points (coefficient
   extraction generalizes to E ⊇ F).

## 2. Generalize `BiniusArg(F, max_tables)` to `(F, E)` (MEDIUM)

`arg.zig` still hard-codes `CommittedMlePcs(F, F)`; make it match
`BiniusStark(F, E, ...)` so the product-sum argument benefits from the
extension-mode soundness too.

## 3. Soundness documentation (MEDIUM)

`docs/overview.md` has the informal ≈1/|E| note. Add a `docs/binius.md` with:
- transcript order (public inputs, pins, roots, τ, α_t, sum-check seed, PCS),
- every Schwartz-Zippel application and its error term,
- concrete security level for the default (Gf256, Gf2_128) config,
- the packing/evaluation identity above and its proof.

## 4. More binius AIRs / gadget framework (MEDIUM)

Only the 4-bit adder exists. Add a small constraint DSL (or two more gadgets:
range check, bit-sliced comparison) to demonstrate the constraint system's
generality and to exercise pins + extension mode on non-adder witnesses.

## 5. Performance (LOW)

- Tower `mul` is recursive Karatsuba (~3^7 base ops for Gf2_128): extension
  mode is ~100–1000× slower than GF(256) in ReleaseFast, minutes in Debug.
  Switch to a CLMUL / comb-based carry-less multiply when the platform allows.
- Packing interpolation is O(N^2): additive FFT (Gao–Mateer) for O(N log N).
- `AdditiveFri` commits each layer with a fresh Merkle tree; consider packing
  multiple field elements per leaf and reusing the hasher.

## 6. Proof serialization (LOW)

Prover/verifier exchange in-memory types; no canonical byte encoding for
transport. Needed for real-world usage.
