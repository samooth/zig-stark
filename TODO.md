# TODO — Binius stack (binary-field / BSV)

Current status: zero-check STARK over the tower field with a pluggable
committed-MLE PCS (`BiniusStarkWith`): the O(2^k) `CommittedMlePcs`, the
sub-linear `PackedPcs`, and the sub-linear polylog FRI-Binius PCS
(`fripcs.zig`, FRI-fold in lockstep with the eval sum-check). Extension-field
`(F, E)` soundness mode, boundary pins, and a batched 4-bit adder gadget. 180 tests.

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
