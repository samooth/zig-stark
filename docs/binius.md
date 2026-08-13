# Binius (binary-field) stack: soundness notes

This document records the exact protocol of the `src/binius` stack — the
zero-check STARK with a pluggable committed-MLE PCS, run over a tower-field
pair `(F, E)` — and accounts for every place randomness enters it. The goal is
a per-application error bound and a concrete security figure for the default
`(Gf256, Gf2_128)` configuration. Code references point into `src/binius/`.

## 1. Notation and field tower

| Symbol | Meaning |
|--------|---------|
| `F` | base (witness) binary field, `tower.TowerField(level)` or `field.Gf256`; `F.BITS` bits per element |
| `E` | extension field of `F` (or `E = F`), where the soundness randomness lives |
| `k` | MLE dimension; witness tables have `2^k` entries |
| `{0,1}^k` | boolean hypercube, the constraint domain |
| `m` | number of witness columns |
| `β_r(x)` | `∏_j (x_j + 1 + r_j)`, the Lagrange / Möbius kernel for the point `r` (char 2: `eq(r_j, x_j) = 1 + r_j + x_j`) |
| `δ_p(x)` | `∏_j (x_j + 1 + p_j)` for a pinned point `p` (the same kernel evaluated at a pin) |
| `M.lift` | the zero-cost tower embedding `F → E` (`TowerField.embed`), identity when `E = F` |
| `D` | FRI domain depth, `k + log_blowup`; requires `D ≤ F.BITS` |
| `ρ` | FRI rate `2^{-log_blowup}` |

Witness columns, committed tables and Merkle leaves stay in `F`. Every random
challenge — τ, α_t, the sum-check round challenges, the PCS query point and the
FRI fold challenges — is sampled in `E`. Base-field entries enter `E` arithmetic
by `lift`, which copies the bit string, so the prover never re-commits.

## 2. Protocol and transcript order

The STARK (`BiniusStarkWith(F, E, CP)` / convenience
`BiniusStarkFri(F, E, log_blowup, num_queries)`) has three nested
Fiat-Shamir stages.

**Stage 0 — outer channel** (`stark.zig:143 deriveChallenges`, hash domain
`core.channel.Channel`). Absorb, in order:

1. public inputs (`public_inputs` bytes);
2. every boundary pin as `(col, point, value)` (`stark.zig:156`);
3. the commitment roots, one per witness column, in column order
   (`stark.zig:163`).

Then sample from the channel: τ ∈ E^k (the zero-check point), α_t ∈ E for each
combined constraint (user constraints then pin constraints; `stark.zig:165-171`),
and finally a 32-byte seed that binds the inner sum-check transcript
(`stark.zig:173`).

**Stage 1 — the combined zero-check sum-check.** All constraints are flattened
into one product-sum-check claim (`sumcheck.zig Sumcheck(E)`):

```
0 = Σ_{x∈{0,1}^k} β_τ(x) · Σ_t α_t · Σ_u c_u · ∏_{f∈factors_u} w_f(x)   (+ pin terms)
```

The pin constraints are `δ_p(x)·(w_col(x) + value) = 0`
(`stark.zig:231 buildPinConstraints`), folded into the same sum-check with
their own α_t. Shared tables are `[w_0..w_{m-1}]` followed by the uncommitted
τ-kernel slots `[m..m+k)` and the pin-kernel slots `[m+k..)` (k per distinct
pin point). The inner transcript is seeded with the outer seed
(`sumcheck.zig:57 initBytes`); per round the prover sends the three coefficients
`c`, the transcript absorbs them and samples the round challenge
(`sumcheck.zig:63 absorb`). The claimed sum is 0.

**Stage 2 — one PCS evaluation proof per distinct factor column.** The zero-check
sum-check terminates at a challenge vector `r' ∈ E^k` and a terminal claim. The
verifier needs `w_f(r')` for every factor column `f`; these are obtained from the
committed roots by the PCS (`stark.zig:515`). Each PCS runs its *own* transcript:

- `CommittedMlePcs(F, E)` (`pcs.zig`): proves `f(r) = Σ_x f(x)β_r(x)` by a
  second degree-2 sum-check whose transcript is seeded from `r`
  (`pcs.zig:54 seedFor`) and bound to the Merkle root (`MlePcs`).
- `FriPcs(F, E, log_blowup, num_queries)` (`fripcs.zig:239`): the polylog
  PCS, described in §5.
- `PackedPcs(F, E)` (`packed_pcs.zig:36`): row packing + column Merkle, §6.

The verifier then recomputes the terminal value of the zero-check combination
from the returned `value_of[f]` and the closed forms of the kernel slots:
`β_τ` gives `τ_j + 1 + r'_j` and the pin kernel gives `p_j + 1 + r'_j`
(`stark.zig:525-541`), and checks it equals the sum-check terminal claim.

Every commitment root is absorbed *before* the corresponding challenges are
sampled, and every proof element is absorbed before the next challenge is drawn,
so the transcript is a correct Fiat-Shamir transformation: the prover's messages
are bound to a public random oracle. Breaking soundness therefore requires
either an algebraic forgery (bounded by the Schwartz-Zippel terms below) or a
hash collision / Merkle forgery (Blake3, ~2^256). No commitment is opened at a
point chosen after seeing its root.

## 3. Schwartz-Zippel applications and error terms

Each challenge below is uniform over `E`, so a non-identity polynomial of
individual degree ≤ d vanishes at a random point with probability ≤ `d/|E|`
(Schwartz-Zippel; char-2 fields are fine, the standard field theorem).

**S1 — the combination coefficients α_t** (`stark.zig:171`). If any combined
constraint polynomial does not vanish on the hypercube, the random combination
`Σ_t α_t R_t` is the zero function with probability ≤ `1/|E|`. Error `1/|E|`.

**S2 — the zero-check point τ ∈ E^k** (`stark.zig:167`). Conditioned on the
combination `R(x) = Σ_t α_t R_t(x)` being a nonzero multilinear polynomial, the
reweighted hypercube sum `S(τ) = Σ_x R(x)·β_τ(x)` is exactly the Möbius
transform of `R`, a nonzero polynomial of individual degree 1 in τ, so it
vanishes on a fraction ≤ `1/|E|` of τ. Error `≤ 1/|E|`.

**S3 — the zero-check sum-check round challenges** (`sumcheck.zig:108`). The
round polynomial has degree at most `D_SC = max_t (|factors_t| + k)` over all
user and pin monomials (`stark.zig:207 maxDegree`, an upper bound: the
τ-kernel slot plus every factor column contribute at most one degree per
variable), so a cheating prover's round polynomial agrees with the true one on
at most a `D_SC/|E|` fraction of challenges; over `k` rounds, union bound
`≤ k·D_SC/|E|`. For the k = 4 4-bit adder: user monomials have ≤ 2 factors
(`adder.zig:65`) and the pin constraints have `k+1 = 5` factors
(`stark.zig:267`), so `D_SC = 2k+1 = 9`.

**S4 — the `CommittedMlePcs` eval sum-check** (`pcs.zig`). Proves
`f(r') = Σ_x f(x)β_{r'}(x)`; each round polynomial is quadratic (product of an
affine `f`-fold and the affine kernel factor), so the error is `≤ 2k/|E|`.

**S5 — the `FriPcs` fold challenges** (`fripcs.zig:504`). The lockstep
sum-check/FRI fold, §5, samples `k` fold challenges; each round polynomial is
degree ≤ 2, error `≤ 2k/|E|`. The FRI proximity test contributes separately,
§5.

**S6 — the `PackedPcs` column queries** (`packed_pcs.zig:29`). A false
row-combination is a nonzero polynomial of degree `< 2^{k2}` vanishing on a
random extended column with probability `≤ 2^{-log_blowup}`; `q` sampled
columns give `2^{-log_blowup·q}`.

**Merkle / hash.** All roots and per-round layer roots are binding commitments
(Blake3). No term from the hash side beyond a collision.

### Total error

For the STARK with `CommittedMlePcs`:

```
ε  ≤  (1 + D_SC + k·D_SC + 2k)/|E|        (union bound, S1-S4)
```

For the STARK with `FriPcs` (§5):

```
ε  ≤  (1 + D_SC + k·D_SC + 2k)/|E|  +  ε_FRI        (S1, S2, S3, S5)
```

`ε_FRI` is the low-degree proximity term, §5. `PackedPcs` contributes S6 in
place of S4/S5.

## 4. Concrete security for the default `(Gf256, Gf2_128)` config

The default sound configuration is `F = Gf256`, `E = tower.Gf2_128`
(`tower.zig` level 7, `|E| = 2^128`). With, e.g., the k = 4 4-bit adder
(`D_SC = 9`):

- S1: `2^-128`
- S2: `2^-128`
- S3: `4·9·2^-128 = 36·2^-128`
- S4/S5 (eval): `8·2^-128`
- hash (Blake3): `2^-256`

Combined algebraic error ≈ `2^-128 · 46 ≈ 2^-123`, i.e. the extension field is
the security bottleneck, not the field arithmetic — this is exactly the point of
running the protocol in `E`. For `PackedPcs`, add `2^{-log_blowup·q}`, and for
`FriPcs` add the FRI proximity term.

**Why not single-field?** `BiniusStark(Gf256, Gf256)` replaces every
`1/|E|` above by `1/|F| = 1/256 = 2^-8`; the same argument gives ≈ `2^-8` — too
weak by itself. The size/e2e tests run single-field *only* because the proof
structure is identical; the sound configuration is the extension pair.

**Query count.** For `FriPcs`, the proximity term depends on the number of
queries (next section); to reach ≈ 2^-128 with `log_blowup = 1` you need
`num_queries ≥ 128`, or fewer queries with a larger blowup. The parameter is
public and checked (`fripcs.zig:477`, `num_queries ≤ 2^{k+log_blowup-1}`).

## 5. The polylog FRI-Binius PCS (`fripcs.zig`)

`FriPcs(F, E, log_blowup, num_queries)` proves `f(r')` for the committed
multilinear `f` in `O(k)` rounds. Protocol:

1. **Commit.** Encode the table with the additive NTT at rate `2^log_blowup`
   (`Ntt.encode`), lift to `E`, and Merkle-commit *adjacent pairs* as leaves
   (`pairHash`, `fripcs.zig:181`); `root0` is the stage-2 transcript seed.
2. **Lockstep eval sum-check + FRI fold, k rounds** (`fripcs.zig:499`). Per
   round: absorb the claimed value, then the three coefficients `c`; check
   `c_1 + c_2 = claim` (the `p(0)+p(1)=claim` test in char 2); sample the fold
   challenge `ch_j`; update `claim = c_0 + c_1·ch_j + c_2·ch_j²`; absorb the
   folded layer root. Each layer is folded by `foldCodeE` with the round's
   twiddle (`fripcs.zig:537`).
3. **Final check** (`fripcs.zig:510-516`), the soundness-critical step:
   ```
   claim_k == final_folded · ∏_{j<k} (1 + r_j + ch_j)
   ```
   Derivation: after `k` folds the code is a constant equal to `f(ch)`, the
   multilinear `f` evaluated at the *fold challenges* (each fold substitutes one
   variable). The eval sum-check's claim, however, tracks the kernel
   `β_{r'}(x) = ∏_j (1 + r'_j + x_j)`; folding the kernel at `ch` leaves the
   residual `∏_j (1 + r'_j + ch_j)`, so the honest terminal claim is exactly
   `f(ch)·∏_j (1 + r'_j + ch_j)`. The reference verifier only checks
   `c_1 + c_2 = claim` per round — satisfiable by arbitrary coefficients — and
   never binds the final claim to the folded code; our check closes that gap
   (the fold identity `fold^k(code) == Σ f·eq_r` is also pinned by the
   `testFoldIdentity` unit test). Note the check uses the *sampled* `ch_j`, not
   the eval point `r'_j`: a naive `claim_k == final_folded` would be wrong.
4. **Proximity.** `num_queries` leaves are opened across all layers against
   their per-layer roots (`fripcs.zig:518-538`); each opened pair must fold with
   the round challenge and twiddle to the expected child.

Soundness of the PCS = eval-sum-check error (S5, `2k/|E|`) + proximity. For the
proximity term we rely on the standard FRI statement: a word at relative
distance ≥ `1 - √ρ` from the code at rate `ρ = 2^{-log_blowup}` is rejected with
probability ≥ `1 - (1-ρ-√ρ)^{num_queries}` (plus a negligible suffix/coset
term); we quote the common informal bound `ε_FRI ≈ (1 - ρ)^{num_queries}` and
note that the precise statement is subtle (proximity, not promise, bounds), so
in practice the query count is chosen conservatively. Parameters are
constrained by `log_blowup ≥ 1` (rate-1 FRI gives no proximity), `D = k +
log_blowup ≤ F.BITS`, and `num_queries ≤ 2^{D-1}` (`fripcs.zig:471-477`).

## 6. The packing / evaluation identity (`pack.zig`)

`PackedMle(F)` supports the `PackedPcs` route via the polynomial identity

```
f(r) = d · [x^{N-1}] ( g · B_r  mod  Z_H )
```

where `N = 2^k`, `H` is the GF(2)-subspace `{fromInt(j) : j < 2^k}` of dimension
`k` (`F.BITS ≥ k`), `Z_H(x) = ∏_{y∈H}(x + y)` is the vanishing polynomial of `H`
(a monic linearized polynomial of degree `N`), `g` is the packed polynomial
`g(x) = Σ_i f(i)·λ_i(x)` with the normalized Lagrange basis
`λ_i(x) = Z_H(x)/(x + x_i) / d`, `d = Z_H'(x) = ∏_{z∈H∖{0}} z` (constant on `H`),
and `B_r(x) = ∏_j (x^{2^j} + r_j)` is the Möbius transform whose restriction to
`H` is the kernel: `B_r(i) = β_r(i)`.

**Proof.** On `H`, the basis is idempotent: for `i ≠ j` the product
`λ_i·λ_j` is divisible by `Z_H` (both vanish at all `y ≠ i,j`... every point of
`H`), and `λ_i² ≡ λ_i (mod Z_H)`. Reducing the degree-`2N-2` product
`g·B_r` modulo `Z_H` therefore gives

```
g·B_r ≡ Σ_i f(i)·β_r(i)·λ_i   (mod Z_H).
```

Each `λ_i` is monic of degree `N-1`, so the coefficient of `x^{N-1}` in the
residue is `(1/d)·Σ_i f(i)β_r(i) = f(r)/d`, and the identity follows. The
verifier who holds the packed `g` (committed per-row, `packed_pcs.zig`) computes
the residue's top coefficient in `O(N)` and checks it against `f(r)` — this is
the scalar check at the end of the `PackedPcs` protocol (S6). For a subfield `H`
of `F`, `Z_H' ≡ 1` so `d = 1`.

## 7. Where each check lives

| Concern | Location |
|---------|----------|
| Transcript, τ/α_t/seed sampling | `stark.zig:143` (`deriveChallenges`), `core/channel` |
| Zero-check sum-check, round challenges | `sumcheck.zig` (`Sumcheck(E)`, `runRounds`, `absorb`) |
| Per-variable degree bound | `stark.zig:207` (`maxDegree`) |
| Pin indicator constraints | `stark.zig:231` (`buildPinConstraints`) |
| Terminal zero-check identity | `stark.zig:525-541` |
| Committed PCS eval | `pcs.zig` (`CommittedMlePcs`, `MlePcs`) |
| FRI lockstep fold + final check | `fripcs.zig:464` (`verifyEval`), `fripcs.zig:510-516` |
| Packing identity / eval | `pack.zig:8-26`, `packed_pcs.zig:29` |

## 8. Memory model (caller-deinit convention)

The stack follows a single ownership rule: **whoever allocates owns and
releases**, so the caller is responsible for freeing every object handed back by
the API. Concretely:

- **Every public `Proof` type owns its heap memory** and exposes
  `deinit(self: *Proof, allocator) void`. Call it with the *same* allocator that
  was passed to `prove`/`proveEval`/`commit`. Proofs are plain value types, so
  the binding holding one must be declared `var` for the deferred `deinit` to
  take a mutable pointer:
  `var proof = try S.prove(alloc, ...); defer proof.deinit(alloc);`
- **`MerkleTree` carries its own allocator** and exposes `deinit(self: *MerkleTree)`,
  e.g. `var tree = try CP.commit(alloc, table); defer tree.deinit();`.
- **Inputs are always borrowed.** Tables, roots, traces, public inputs, pins and
  constraints passed *into* the API are never freed or mutated by the library.
  Slices copied into a proof (e.g. `CommittedMlePcs.Proof.entries`) borrow the
  prover's table and must outlive the proof.
- **`verify` never modifies or frees proof memory.** It may allocate its own
  temporaries (challenges, query lists) which it frees before returning, on both
  the accept and reject paths. Rejected proofs therefore must still be released
  by the caller with `deinit`.
- Helper builders return owned memory: `kernelTables`, `deriveChallenges`
  (`tau`/`alphas`), `liftTables`, FRI `commit`, PCS `rootOf` — the caller frees
  each slice and (for `[][]T` results) each inner slice.
- All library tests run against `std.testing.allocator` so every test is
  leak-checked; the suite will fail on any un-freed allocation.

