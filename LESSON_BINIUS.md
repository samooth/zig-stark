# LESSON_BINIUS.md

Session notes on the binary-field (Binius/BSV) stack in `src/binius`, gathered
over the polylog FRI-PCS landing, the proof-size milestone, the `(F, E, PCS)`
generalization, the soundness documentation (§3), CLMUL (§5), the memory-model
/caller-deinit leak sweep, the runtime-caps change, and the bit-pack gadget.
Companion to `LESSON_STARK.md` (m31 stack math) and `LESSON_ZIG.md` (toolchain
quirks).

## FRI PCS soundness: the final check is not vacuous

- The polylog PCS (`fripcs.zig`) FRI-folds the additive-NTT code in lockstep
  with the evaluation sum-check: k rounds, each sending the univariate
  coefficients `c = [p(0), claim + p(∞), p(∞)]`, the verifier checking
  `c1 + c2 == claim` (char 2: `p(0) + p(1) == claim`), sampling the fold
  challenge `ch_j`, and folding the claim to `c0 + c1·ch + c2·ch²`.
- The reference verifier (HiddenAndBound) only checks that round identity and
  never binds the final claim to the fully folded code — but `c1 + c2 == claim`
  is satisfiable by arbitrary coefficients, i.e. *vacuous*. A buggy prover gets
  through every round and the reference accepts.
- The correct terminal check is
  `claim_k == final_folded · ∏_j (1 + r_j + ch_j)` where `r` is the eval point.
  Derivation: after k folds the code is a *constant* equal to `f(ch)` (the
  multilinear evaluated at the sampled fold challenges, because each fold
  substitutes one variable), while the sum-check's claim tracks the kernel
  `β_r(x) = ∏_j (1 + r_j + x_j)`; folding the kernel at `ch` leaves the residual
  `∏_j (1 + r_j + ch_j)`, so the honest terminal claim is exactly
  `f(ch)·∏_j (1 + r_j + ch_j)`.
- Why it is NOT `claim_k == final_folded`: the fold challenges are *sampled*,
  not equal to the eval point. A naive `== final_folded` (or `== f(r)`) check is
  wrong. The fold identity `fold^k(code) == Σ v·eq_r` is pinned numerically by a
  `testFoldIdentity` unit test.
- This is the general lesson: never trust a reference verifier's final check to
  be binding; derive it yourself and validate the derivation numerically.

## E2E debugging: roots must come from the same PCS as prove

- When wiring FRI into the STARK e2e, tamper-rejection "passed" spuriously for
  every tampered case. Root cause: the e2e had committed with `FriPcs` but
  verified with roots laid out by `CommittedMlePcs` (single-element leaves).
  `FriPcs` Merkle leaves are *pairs* (`pairHash(a, b)`), so the root layout is
  different. The verifier was checking against a root the prover never
  committed to — any transcript replay that survived the pair-fold check at all
  looked consistent.
- Lesson: the commitment root is PCS-specific. Whenever the PCS is a parameter,
  both `prove` and `verify` must build roots through the *same* PCS type; a
  tamper test that can never pass its checks is as useless as one that always
  does.

## FRI parameter constraints

- `log_blowup ≥ 1` is required: rate-1 FRI gives no proximity at all.
- `D = k + log_blowup ≤ F.BITS` (the additive domain is a GF(2)-subspace of the
  field; the tower `Gf16`/`Gf256` cap `D` at 4/8).
- `num_queries ≤ 2^(D-1)` because leaves are pairs; at `k = 1` there are only
  two leaves, so queries are capped at 2.

## Proof-size tests: run single-field, measure growth rate

- The proof-size e2e runs with `F = E = Gf256` (single-field) in Debug because
  the eval-section *size structure* is identical across `(F, E)` while
  extension-mode proving over `Gf2_128` takes minutes at k ≥ 5 in Debug.
- Assert the *growth rate*, not just absolute size: FRI eval sections grow
  `< 2×` per k step while the committed-MLE sections double; FRI wins at k = 6
  (measured 3008 vs 7184 units, ≈ 2.4×). Size units are the sum of value +
  sum-check + openings, not proof bytes.

## `std.debug.print` in tests under the Zig build runner

- `std.debug.print` from a test run through `zig build test` (which uses
  `--listen=-`) produces a spurious `failed command` line in the runner output
  even though the test summary reports success. It is cosmetic, but it makes CI
  logs alarming; remove the prints from committed tests.

## BiniusArg mirrors the STARK exactly

- `arg.zig` was generalized the same way the STARK was: `BiniusArg(F, E)`
  stays the single-field alias, `BiniusArgWith(F, E, CP)` lifts the F tables
  into E via the zero-cost embedding (`E.embed(F.LEVEL, x)`, identity for
  `E = F`) and runs the product sum-check over E with a pluggable PCS, and
  `BiniusArgFri(F, E, log_blowup, q)` wires in `FriPcs`. Keeping one
  construction shape (STARK and arg both `(F, E, CP)`-parameterized) means
  every PCS/field improvement lands in both at once.

## Soundness accounting: every Schwartz-Zippel application, with its error term

Nested Fiat-Shamir stages: outer channel (public inputs → pins → roots → τ,
α_t, seed), the combined zero-check sum-check (seeded by the outer seed → k
round challenges `r'`), and per-PCS transcripts (root → PCS challenges +
queries). Each challenge is uniform over E; a nonzero polynomial of individual
degree ≤ d vanishes with probability ≤ d/|E|.

| Application | Error |
|---|---|
| combination coefficients α_t | `1/|E|` |
| zero-check point τ ∈ E^k | `1/|E|` — the Möbius transform has individual degree 1, NOT `deg+1` |
| zero-check sum-check rounds | `k·D_SC/|E|`, `D_SC = max_t(|factors_t| + k)` (`stark.zig` `maxDegree`) |
| `CommittedMlePcs` eval sum-check | `2k/|E|` (quadratic rounds) |
| `FriPcs` fold challenges | `2k/|E|` + proximity |
| FRI proximity | `≈ (1 - ρ)^num_queries`, `ρ = 2^-log_blowup` |
| `PackedPcs` column queries | `2^{-log_blowup·q}` |

- The initial analysis wrongly credited the τ-check with error `D_SC/|E|`;
  `Σ_x R(x)β_τ(x)` is the Möbius transform of R, a nonzero polynomial of
  *individual degree 1*, so the right term is `1/|E|`.
- `D_SC` counts the τ-kernel slot plus every factor column per variable; the
  pin constraints have `k + 1` factors, so for the k = 4 4-bit adder
  `D_SC = 2k + 1 = 9` (user monomials have ≤ 2 factors).
- Concrete default `(Gf256, Gf2_128)`, k = 4: algebraic error ≈ `46·2^-128 ≈
  2^-123`, i.e. the extension field is the security bottleneck, not the
  arithmetic. Single-field `(Gf256, Gf256)` would be ≈ `2^-8` per application —
  too weak alone; that is the whole reason for running the protocol in E.
- FRI proximity dominates: to reach ≈ 2^-128 with `log_blowup = 1` you need
  `num_queries ≥ 128`, or fewer queries with a larger blowup.

## The packing / evaluation identity

`f(r) = d · [x^(N-1)] ( g · B_r  mod  Z_H )` with `N = 2^k`, `H` the
GF(2)-subspace `{fromInt(j)}`, `Z_H` its (monic, linearized) vanishing
polynomial, `g` the packed polynomial, `d = Z_H'(x) = ∏_{z∈H∖{0}} z` (constant
on H; `d = 1` when H is a subfield), and `B_r(x) = ∏_j (x^{2^j} + r_j)` the
Möbius transform (equal to `β_r` on H). Proof: the Lagrange basis is idempotent
mod `Z_H` (`λ_i² ≡ λ_i`, `λ_i·λ_j ≡ 0`), so `g·B_r ≡ Σ_i f(i)β_r(i)λ_i`; each
`λ_i` is monic degree `N-1` with leading coefficient `1/d`, giving the top
coefficient `f(r)/d`.

## CLMUL multiplication of the tower field (in progress, §5)

- **The Cantor/multilinear basis is NOT a polynomial basis** — there is no
  single modulus Q with `{∏ X_i}` = `{1, y, …, y^(BITS-1)}`. Consequence: the
  carry-less product of two elements' *bit strings* is NOT their field product.
  Interpreting the bits as `Σ a_j x^j` with `x ↦ X_0` collapses everything into
  the GF(4) subfield — wrong. So "CLMUL + reduce mod a fixed polynomial" only
  works after a change of basis.
- Correct recipe: find a generator `g` (powers span ⇔ V invertible ⇔ minimal
  polynomial Q has degree BITS); then
  `a·b = V · ( (V⁻¹·a) · (V⁻¹·b) mod Q )` where V's columns are the Cantor
  representations of `g^0..g^(BITS-1)`, `(V⁻¹·a)` is the polynomial-basis
  coordinate vector, the product is a 128×128→256 carry-less multiply, and the
  reduction mod Q is a precomputed linear map. All linear maps are applied
  column-wise over GF(2): `out = ⊕_{set bits j} col[j]`.
- `Q` comes for free: from `g^BITS`, `q = V⁻¹ · g^BITS`; reduction columns are
  the iterated `x^j mod Q` (`x·c mod Q` = shift, and if the top bit was set XOR
  the q coefficients).
- This replaces the recursive Karatsuba (3^7 ≈ 2187 base ops per Gf2_128 mul)
  with ~4 CLMULs + a few hundred u128 XORs.
- **Comptime generation of these tables is far too slow in the Zig
  interpreter** (generator search does BITS recursive tower muls): it exceeded
  a 16M backwards-branch quota and took ~90 s to fail. `@setEvalBranchQuota`
  only postpones the pain. Build the tables lazily at runtime instead (see
  LESSON_ZIG.md); runtime cost is microseconds.
- Keep `mulRec` (the recursion) as the portable fallback and as the reference
  for cross-checks; cross-check `mulFast == mulRec` exhaustively for GF(4),
  GF(16), GF(256) and randomly at every level.
- Only enable the fast path where it pays (hardware CLMUL present, and probably
  level ≥ 4–5); small fields are already cheap.

## Memory model: caller-deinit, and the errdefer/return-null trap

- Ownership rule across the stack: **whoever allocates owns and releases**. Every
  public `Proof` exposes `deinit(self: *Proof, allocator)` (same allocator as
  `prove`), `MerkleTree` carries its allocator (`deinit(self: *MerkleTree)`),
  inputs passed in are borrowed, and `verify` never frees proof memory — a
  rejected proof is still deinit'd by the caller. `arg.Proof.evals` became
  `[]EvalProof` (mutable) so nested PCS proofs can be released.
- **The 5-leak suite failure was a reject-path leak, not a memory-model gap.**
  `sumcheck.runRounds` freed `challenges` with `errdefer`, but the 
  consistency-check failure path is `return null` — and **`errdefer` does not
  run on `return null`**. A tampered root changes the transcript-seeded
  challenge, a later round check legitimately fails, and `challenges` leaks.
  This made *every* invalid-proof test leak. Fix: free before `return null`.
- Second library leak: the pin path moved the inner `kernelTables` tables into
  `pin_tables` but dropped the outer `[][]E` container — one `allocator.free(pt)`
  after the move closes it.
- De-arenaring: ~45 arena-wrapped tests converted to `std.testing.allocator`;
  only the intentional prover-side scratch arenas (fripcs.zig
  312/340/486) remain. The sweep surfaced proofs/trees/witness copies that were
  never freed — documented in `docs/binius.md` §8.

## Runtime caps: drop comptime max_cols / max_tables

- `BiniusStark(F, E)` and `BiniusArg(F, E)` are back to pure field-typed
  signatures; the comptime caps and `MaxColumns`/`MaxTables` are gone. All
  cap-sized arrays (roots, `seen`, `distinct`, `value_of`) are heap-allocated
  at the actual column count, and `seedForRoots` streams through the channel
  instead of packing `[max_tables*32]u8`. `*With` is the canonical interface,
  `*Fri(F, E, log_blowup, q)` the sub-linear one.

## Bit-pack gadget: pack as a zero-check constraint

- `BitPack(F, E)` / `BitPackWith(F, E, CP)`: each hypercube point holds one
  `num_bits = F.BITS`-wide value `v` plus `num_bits` boolean bit columns. The
  `num_bits + 1` constraints are booleanity (`b_i + b_i² = 0`) plus one pack
  equation `v = Σ_i b_i·e_i`, `e_i = fromInt(1<<i)`. Because the tower bit
  string is the coefficient vector in the standard basis, this is a field
  identity — so a verifier can commit bit columns and enforce the numeric
  value. Column layout `b_0..b_{num_bits-1}, v`; witness is
  `generateWitness(alloc, []const UInt)` with `UInt = std.meta.Int(.unsigned,
  num_bits)`.
- This is the primitive for range checks and bit manipulation; the adder's sum
  column could be replaced by `BitPack` + an equality gate. Range check `v < W`
  for a power-of-two `W` is just "the top `num_bits - log2(W)` bit columns are
  boolean-and-zero".
- Rejection tests must violate *every* point: a single-cell non-boolean value
  is a point violation whose MLE vanishes for most τ in a small field; a whole
  column of `2`s gives `Σ_x R(x)β_τ(x) = α ≠ 0` for any α ≠ 0 (soundness
  `1 - 1/|F|` in the combination coefficient).

## Batch openings (M2, implemented)

- The per-query opening cost was the last big proof-size factor. The design in
  `docs/binius.md` §9 proposed a λ-combiner, but that binds only the
  combination — the STARK's zero-check/product checks need each individual
  column value, so a combiner would need an extra per-column soundness term
  per batch. The implemented `src/binius/batchpcs.zig` instead shares *one
  Merkle tree per FRI layer* across all columns: every column runs its own eval
  sum-check and folds with its own per-column challenge, but each folded layer
  is committed as a single tree whose leaves hash all columns' `(folded, next)`
  pairs, so one query path per round serves every column (soundness unchanged —
  each claim stays individually bound by the per-column fold identity).
- `stark.zig` dispatches with `@hasDecl(CP, "proveEvalBatch")`; `Proof.evals`
  is a tagged union `if (has_batch) CP.BatchProof else []EvalProof`, and the
  prove/verify paths branch on it (gather `distinct` columns + roots, one
  `proveEvalBatch`/`verifyEvalBatch` call, fill `value_of` from the batch's
  `.values`). `BiniusStarkFri` now uses `BatchFriPcsStark`; `BiniusArgFri`
  keeps the per-column `FriPcs` (it does not open all its tables at one point
  via the STARK), and the k=4..6 size test covers both proof shapes through
  `friEvalUnits` (`@hasField` dispatch on the eval section).
- Remaining design options (still future work): λ-combined FRI queries, a
  Brakedown-style batched sumcheck, and tower-size-1 packing.

## Range check, comparison, and the constraint DSL

- `RangeCheck(F, E, m)` is literally `BitPack` with a parameterized bit count
  (`m ≤ F.BITS`): `m` booleanity + one pack equation. A range check in
  `[0, 2^m)` is "the bit columns are boolean and pack to the value".
- `Compare(F, E, m)` uses the classic eq/lt chains with `eq_m = 1`, `lt_m = 0`
  (result is `lt_0`): `eq_i = eq_{i+1} ∧ (a_i = b_i)`, `lt_i = lt_{i+1} ∨
  (eq_{i+1} ∧ a_i < b_i)`, enforced as `eq_i + eq_{i+1}(1 + a_i + b_i) = 0` and
  `lt_i + lt_{i+1} + eq_{i+1}(b_i + a_i b_i) = 0`.
- **Constant terms are legal.** I first assumed the zero-check was a plain
  hypercube sum (where a constant contributes `Σ_x 1 = 2^k ≡ 0` in char 2) and
  built a constant-free `ne` chain. That was wrong: the zero-check evaluates at
  a random point via `Σ_x C(x)·β_τ(x) = C(τ)`, and `Σ_x β_τ(x) = 1`, so `eq_m =
  1` as a constant monomial (`&.{}` empty factors) is sound. The round-trip
  still failed after the rewrite, and the bug was different: I'd left
  un-premultiplied `b_i + a_i b_i` terms in the `lt` constraint (from the old
  `ne` design), turning `lt_i + lt_{i+1} + eq_{i+1}(b_i + a_i b_i) = 0` into
  `lt_i + lt_{i+1} + (1 + a_i)b_i(1 + eq_{i+1}) = 0`. Symptom: prove succeeds,
  verify rejects. Lesson: when a recurrence has a "base" like `eq_m = 1`, the
  factored `(b + ab)` terms must be premultiplied by the chain factor for the
  general case and dropped there — only the base case gets the bare terms.
- **The DSL.** `src/binius/constraints.zig`: a comptime `Builder(C, n,
  max_terms)` with `add(t, coeff, factors)`, `@"bool"` (the primitive `bool`
  must be `@"bool"`-quoted to reference the type), and `finish()` returning a
  `comptime const` pool — a comptime `var` can't be referenced by a global
  `constraints` array, so the pool must be materialized by a comptime function
  returning by value. `shiftInto` appends another gadget's constraints with a
  column offset for composition.
- **The combined example** (`binius_rangecmp`) shows the payoff: two range
  checks + one comparison in one proof, with 8 *linear* value links equating
  the range-check bit columns to the compare's `a`/`b` columns (a linear
  combination per link). With the links, the range-checked values ARE the
  compared ones, so the statement is genuinely "this sequence is strictly
  increasing and bounded in `[0, 16)`" with `seq[0]`, `seq[n]` pinned as public
  boundary inputs. A forged witness violating either property (an out-of-range
  value at one point, or one swapped unordered pair) is rejected.
