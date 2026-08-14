# TODO — Binius stack (binary-field / BSV)

Current status: zero-check STARK over the tower field with a pluggable
committed-MLE PCS (`BiniusStarkWith`): the O(2^k) `CommittedMlePcs`, the
sub-linear `PackedPcs`, and the sub-linear polylog FRI-Binius PCS
(`fripcs.zig`, FRI-fold in lockstep with the eval sum-check). Extension-field
`(F, E)` soundness mode, boundary pins, and five gadgets (4-bit adder,
bit-pack, range check, comparison, constraint DSL). 205 tests (196 unit + 9
end-to-end).

## 1. Sub-linear MLE evaluation / commitment (HIGH, DONE — polylog route landed)

### Polylog FRI route — IMPLEMENTED in `src/binius/fripcs.zig`

`FriPcs(F, E, log_blowup, num_queries)` + `FriPcsStark` (adapter for
`BiniusStarkWith`), e2e-wired into the 4-bit adder. Protocol (DP24 eprint
2024/504 / FRI-Binius, scalar form):

1. **Commit.** Encode the table v with the additive NTT at rate 2^log_blowup,
   lift to E, and Merkle-commit adjacent *pairs* as leaves.
2. **Sum-check + FRI fold in lockstep (rounds = k).** Per round the prover
   sends the univariate sum-check coefficients `c = [eval_at_0, claim+eval_at_inf,
   eval_at_inf]`, the verifier samples the fold challenge, both fold the mle/eq
   tables with `fold_lo` and the code with the twiddle fold `foldCodeE`
   (v = A+B, u = A + v·t, fold = u + (v+u)·r, t = Ŵ_round at the pair's coset
   point), and each folded layer is Merkle-committed and bound to the
   transcript.
3. **Final check (soundness fix, absent in the reference verifier).** The fully
   folded code is *constant* and equals `code_k[0] = Σ v[i]·eq_challenges(i)`
   (verified numerically for all fields). Because the fold challenges are
   *sampled* (not the eval point), the eq-kernel does NOT fold to 1; the
   correct check is
       claim_k == final_folded · ∏_j (1 + r_j + ch_j)   (derived & tested)
   Then run `num_queries` FRI queries: each pair is opened against its layer's
   root, folded with the round challenge and twiddle, checked for consistency
   with the parent layer, and the final folded value must equal
   `final_folded_value`.
4. **NTT.** `Ntt(F)` implements the LCH14 "novel polynomial basis" additive NTT
   (normalized subspace polynomials Ŵ_i, twiddles in counting order) with
   `encode`, `forwardTransform` (coset blocks), and the twiddle `foldCode`.
   The fold identity `fold^k(code) == Σ v·eq_r` is pinned by tests
   (`testFoldIdentity`), resolving the old "pin ordering" TODO.

Notes:
- `log_blowup ≥ 1` required (rate-1 FRI gives no proximity); `D = k +
  log_blowup ≤ F.BITS`.
- The reference (HiddenAndBound) verifier only checks `oracle(0)+oracle(1) ==
  claim` per round (vacuous) and never binds the final claim to the folded
  value; our `claim_k == final_folded·∏(1+r_j+ch_j)` check closes that gap.
- Reuses the core Merkle + Blake3 transcript; proofs own their memory
  (`Proof.deinit`).
- **DONE — default wiring.** `BiniusStarkFri(F, E, log_blowup, num_queries)`
  in `stark.zig` exposes the zero-check STARK with `FriPcs` as
  its PCS; the 4-bit adder e2e uses it, and `BiniusStark` remains the O(2^k)
  `CommittedMlePcs` oracle. The proof-size test (`tests/e2e_tests.zig`,
  single-field Gf256 for Debug speed) runs both PCS at k = 4..6 and asserts
  (a) the FRI eval-section units grow < 2x per k step while the committed
  ones double, and (b) FRI wins at k = 6 (~2.4x smaller; measured 3008 vs
  7184 units). Runtime note: extension-mode (Gf2_128) prove at k ≥ 5 is
  minutes in Debug — keep size tests single-field.

## 2. Generalize `BiniusArg(F, max_tables)` to `(F, E)` — DONE

`arg.zig` now mirrors the STARK: `BiniusArg(F, E)` stays the single-field
construction (alias), `BiniusArgWith(F, E, CP)` runs the product sum-check
over the extension field `E` (F tables lifted by the zero-cost tower
embedding) with a pluggable PCS, and `BiniusArgFri(F, E, log_blowup, q)` wires
in the polylog `FriPcs`. Tests cover extension-mode round trips, FRI round
trips (single-field Gf256 and extension Gf16/Gf2_128), tamper rejection (wrong
sum, wrong root), and an e2e proof-size check (k = 4..6, single-field)
mirroring the STARK one. Runtime note: extension-mode sum-checks are slow in
Debug — keep the FRI proof-size test single-field.

## 3. Soundness documentation — DONE

`docs/binius.md` records the exact transcript order (outer channel →
zero-check sum-check → per-PCS transcripts), every Schwartz-Zippel application
with its error term (combination α_t, zero-check point τ, sum-check round
challenges, eval sum-check, FRI fold challenges, PackedPcs column queries),
the concrete `(Gf256, Gf2_128)` figure (~2^-123 algebraic error), the
`claim_k == final_folded·∏(1+r_j+ch_j)` final-check derivation, and the
packing/evaluation identity with proof. `docs/overview.md` keeps the informal
≈1/|E| note.

## 4. More binius AIRs / gadget framework (DONE — range check + comparison + DSL)

The 4-bit adder, the bit-pack gadget (`src/binius/bitpack.zig`), the range
check (`src/binius/rangecheck.zig`, `RangeCheck(F, E, m)` bounds a value in
`[0, 2^m)` via `m` booleanity + one pack equation), and the bit-sliced
comparison (`src/binius/compare.zig`, `Compare(F, E, m)` proves `<` / `==`
with eq/lt chains and a constant `eq_m = 1` base, legal because the zero-check
evaluates `C(τ)` rather than summing over the hypercube) are the reference
implementations of the `BiniusStarkWith` interface. The constraint DSL
(`src/binius/constraints.zig`: comptime `Builder(C, n, max_terms)` +
`shiftInto`) composes several gadgets into one proof; `examples/binius_rangecmp`
proves a bounded strictly-increasing sequence with 2 range checks + 1
comparison + 8 value links (26 columns, 34 constraints).

## 4b. Batched / batched-VSB commitments (HIGH, DONE — M2, committed)

M2 landed a batched-eval FRI PCS (`src/binius/batchpcs.zig`): the STARK now
opens every distinct witness column at the sum-check point in one proof whose
FRI layers are shared Merkle trees (one tree per layer hashing all columns'
folded pairs), so a single query path per round serves every column. Each
column keeps its own eval sum-check and fold challenges, so individual claims
stay individually bound. `BiniusStarkFri` uses it via `BatchFriPcsStark`;
`BiniusArgFri` still uses the per-column `FriPcs`. See `docs/binius.md` §9.

## 5. Performance (LOW)

- **CLMUL — DONE** (`src/binius/clmul.zig`, committed `2068ac3`): hardware
  `pclmulqdq` carry-less multiply for the tower `mul`/`mulHi`/`inv` fast path
  with runtime detection and lazy table build; software fallback otherwise.
- Packing interpolation is O(N^2): additive FFT (Gao–Mateer) for O(N log N).
- `AdditiveFri` commits each layer with a fresh Merkle tree; consider packing
  multiple field elements per leaf and reusing the hasher.

## 6. Proof serialization (LOW)

Prover/verifier exchange in-memory types; no canonical byte encoding for
transport. Needed for real-world usage.
