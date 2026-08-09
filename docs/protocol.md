# The DEEP-FRI STARK protocol

This document describes the exact protocol implemented in
`src/m31/stark.zig` and `src/m31/fri.zig`. It is written for readers who want
to verify that the implementation matches a correct DEEP-FRI STARK, and to make
the (occasionally subtle) algebraic identities precise.

Throughout, `F = QM31` is the base field for STARK arithmetic. The trace lives
on the subgroup `H = <w>` of size `n = 2^trace_log`, and all commitments are
evaluations on the larger domain `D = FRI_OFFSET * <w_ev>` of size
`N = 2^(trace_log + log_blowup)`.

## Notation

| Symbol | Meaning |
|--------|---------|
| `n` | trace length `2^trace_log` |
| `N` | evaluation domain length `2^(trace_log + log_blowup)` |
| `shift` | `2^log_blowup`; stepping one row advances `shift` domain points |
| `H = <w>` | trace subgroup, `w = primitiveRootOfUnity(trace_log)` |
| `D` | evaluation coset `FRI_OFFSET * <w_ev>` |
| `Z_H(x) = x^n - 1` | vanishing polynomial of `H` |
| `m` | number of AIR columns |
| `n_pre` | number of preprocessed (table) columns |
| `n_rel` | number of lookup relations |
| `m_total = m + n_rel` | committed trace columns (AIR + accumulators) |
| `C_k` | transition constraint polynomials |

## The AIR interface

An AIR provides:

- `num_columns`, `num_transition_constraints`, `num_boundary`;
- `evalTransition(x, current, next, out)` — writes the transition constraints;
  `x` is the evaluation point, so row-dependent constraints can be written as
  polynomials in `x` (see the `ml_linear` example);
- `boundaryAssertions(public_inputs, n, out)` — fills the boundary assertions
  `(column, step, value)`;
- `maxConstraintDegree(n)` — an upper bound on the degree of any transition
  constraint as a polynomial in `x`; it sizes the FRI commitment for the DEEP
  combination (see the `rescue` example, whose degree-5 sbox requires
  `5*(n-1)`);
- optionally, the LogUp lookup metadata listed below.

The prover interpolates each trace column `f_j` on `H` (a polynomial of degree
`< n`) and evaluates it on `D`; `codewords[j]` is the codeword of `f_j`.

## LogUp lookups (optional)

An AIR can additionally declare lookups, checked with the **LogUp** (logarithmic
derivative) multiset argument. This is fully optional: an AIR without lookups is
unchanged and the `2m + 1`/`m` quantities below all reduce to the plain case.

**Declared metadata.** `GenericStark` inspects the AIR type at compile time:

- `num_preprocessed`: number of preprocessed (lookup table) columns;
- `num_lookup_columns`: number of columns in each combined lookup key;
- `num_lookup_relations`: number of independent lookup relations;
- per relation `r`, the column indices `lookup_selector_columns[r]`,
  `lookup_key_columns[r]` (a list of `num_lookup_columns` trace columns),
  `lookup_table_columns[r]` (the matching preprocessed table columns), and
  `lookup_multiplicity_columns[r]` (the trace column holding the multiplicity).

**Combined keys.** For each relation `r`, after the trace roots are absorbed the
prover samples one challenge `alpha_col[j]` per lookup column and one challenge
`alpha_rel[r]` per relation. Each row's lookup key is the linear combination

```
key_i  = sum_j alpha_col[j] * trace_row[lookup_key_columns[r][j]]
tkey_i = sum_j alpha_col[j] * table_row[lookup_table_columns[r][j]]
```

and the selector `sel_i` and multiplicity `m_i` come from the corresponding
trace columns. The relation then claims the multiset equality

```
sum_i sel_i * m_i / (alpha_rel - key_i)   =   sum_i (1 - sel_i) / (alpha_rel - tkey_i)
```

**Accumulator columns.** For each relation, `GenericStark` appends one extra
trace column at index `m + r` (so `m_total = m + n_rel`). The honest prover
fills it as a running sum over rows with `acc[0] = 0`:

```
acc[i+1] = acc[i] + sel_i * m_i / (alpha_rel - key_i) - (1 - sel_i) / (alpha_rel - tkey_i)
```

With `acc[0] = 0` the last-row wrap `acc[n] = acc[0]` is exactly the statement
that the two sums above are equal. To make this a *single* cyclic constraint
that holds on every row of `H` (including the last, where `acc` wraps), the
prover/verifier use the denominator-cleared identity

```
C_r = sel * [(acc_next - acc)(alpha_rel - key) - m]
    + (1 - sel) * [(acc_next - acc)(alpha_rel - tkey) + 1]
```

which vanishes on each row precisely when `acc` follows the running sum. Because
the accumulator depends on the sampled challenges `alpha`, it is committed in a
**second phase**: preprocessed roots → trace roots → sample `alpha_col`/`alpha_rel`
→ commit accumulator columns → sample transition/boundary weights. Additionally
the selector is constrained to be a bit (`sel(1 - sel) = 0`) and `acc[0] = 0` is
appended to the boundary assertions.

## 1. Commit the trace

For each column `j`:

- interpolate `f_j` from the trace on `H`;
- evaluate `codewords[j][i] = f_j(d_i)` on `D`;
- build a Merkle tree over `hash(f_j(d_i))` and absorb its root into the
  transcript (`Channel`).

Preprocessed columns are committed first (roots absorbed before the trace
roots); the synthesized accumulator columns are committed last, after the
lookup challenges are sampled.

## 2. Sample challenge weights

- absorb all preprocessed and trace roots (in the order committed above);
- sample the lookup challenges `alpha_col[j]`, `alpha_rel[r]` (if any), then
  absorb the accumulator roots;
- sample `num_transition_constraints + 2*n_rel` field elements `alpha_k`
  (transition weights, including the cyclic LogUp and selector-binarity
  weights);
- compute the boundary assertions from the public inputs (deterministic, not
  absorbed) and append the synthesized `acc[0] = 0` assertions;
- sample `num_boundary + n_rel` field elements `beta_k` (boundary weights).

## 3. Build the composition and the quotient

For every domain point `x = d_i` compute

```
current[j] = f_j(x)
next[j]    = f_j(w * x)          // next row
```

and the transition values `res = C(current, next)`. The composition is

```
Hc(x) = sum_k alpha_k * C_k(x) * (x - w^(n-1))
      + sum_r alpha_trans+r * C_r(x)          // cyclic LogUp constraints
      + sum_r alpha_trans+n_rel+r * sel_r(1 - sel_r)
      + sum_k beta_k  * (f_{col_k}(x) - v_k) * Z_H(x) / (x - p_k)
```

where `p_k = w^step_k` is the point of the k-th boundary assertion. The LogUp
constraints and selector-binarity constraints are **cyclic**: they carry no
`(x - w^(n-1))` factor, so they are enforced on every row of `H` including the
last (where the accumulator wraps to `acc[0] = 0`).

The factor `(x - w^(n-1))` on the transition constraints is the standard trick
that allows constraints to be enforced only on `H \ {w^(n-1)}` (the last row has
no well-defined "next"). Each boundary term `(f - v) Z_H / (x - p_k)` is the
unique polynomial equal to `Z_H(p_k) * (f(p_k) - v_k)` at `p_k` and vanishing at
every other point of `H`; on `H` the whole expression is exactly `Z_H(p_k) *
(f(p_k) - v_k)`.

Because `Hc` vanishes on `H`, it is divisible by `Z_H`; the prover evaluates the
quotient pointwise on `D`:

```
q_codeword[i] = Hc(d_i) / Z_H(d_i)
```

commits it, and absorbs the quotient root.

## 4. Sample `z` and compute DEEP evaluations

- sample `z <- F`;
- compute `wz = w * z` and the evaluations
  `deep_evals = [f_j(z), f_j(w*z)  (j = 0..m_total-1),  Q(z)]` (length
  `2*m_total + 1`, where `m_total = m + n_rel` includes the accumulator
  columns);
- `Q(z)` is computed directly by evaluating `Hc(z) / Z_H(z)` (Horner, no
  interpolation of the quotient);
- absorb `deep_evals`;
- sample `2*m_total + 1` DEEP weights `gamma`.

## 5. Commit the DEEP combination via FRI

The DEEP combined polynomial is

```
g(x) = sum_j gamma_j        * (f_j(x)      - f_j(z))   / (x - z)
     + sum_j gamma_{m+j}    * (f_j(w*x)    - f_j(w*z)) / (x - z)
     +       gamma_{2m}     * (Q(x)        - Q(z))     / (x - z)
```

where `m` is replaced by `m_total = m + n_rel` when lookups are present, so `g`
combines the trace, accumulator and quotient codewords.

Every quotient `(p(x) - p(z))/(x - z)` is a polynomial (the quotient of `p` by
`(x - z)`), so `g` has degree `< 2^log_size`. The prover evaluates `g` on `D`
and commits it with FRI (see below).

## 6. Query phase

For each of `num_queries` queries the transcript's `sampleIndex(N)` fixes a
domain index `p0`. The prover reveals (all with Merkle authentication paths,
in **column-major** order):

```
values = [f_0(x0) ... f_{m_total-1}(x0),    // trace + accumulator, x0 = d_p0
          f_0(w*x0) ... f_{m_total-1}(w*x0),
          Q(x0),
          pre_0(x0) ... pre_{n_pre-1}(x0)]  // preprocessed (if any)
```

The verifier checks, for each query:

1. **Merkle authentication** of every revealed value against the committed
   preprocessed, trace, accumulator and quotient roots;
2. **DEEP identity**: the FRI first-layer leaf at `p0` equals
   `g(x0)` computed from the revealed values and `deep_evals`;
3. **Constraint identity**: `Hc(x0) == Z_H(x0) * Q(x0)`, where `Hc(x0)` is
   recomputed from the revealed `current`/`next` values (including the
   accumulator and preprocessed columns) and the boundary assertions.

## FRI

`src/m31/fri.zig` implements FRI over `F = QM31`.

**Domains.** Layer `i` uses `D_i = offset^(2^i) * <w_i>` with
`w_i = primitiveRootOfUnity(dlog - i)`, so `D_{i+1}[j] = (D_i[j])^2`.

**Folding.** With the fold challenge `alpha_i`, layer `i + 1` is defined on
squares:

```
f_{i+1}(x^2) = (f_i(x) + f_i(-x)) / 2
             + alpha_i * x^{-1} * (f_i(x) - f_i(-x)) / 2
```

This halves the degree each round.

**Commit / transcript order.**

1. for each layer `i`: absorb `root_i`, sample `alpha_i`;
2. absorb the remainder;
3. sample the query indices.

**Remainder code.** After `numFoldRounds = (trace_log + log_blowup) -
remainder_log` folds, the final layer has `2^remainder_log` points and is a
codeword of degree `< 2^(remainder_log - log_blowup)`. The prover interpolates a
degree-`< 2^(remainder_log - log_blowup)` polynomial from a strict subset of
those points and sends its coefficients. This is a **proper** code (block length
> dimension whenever `log_blowup > 0`), so a committed codeword that is not
low-degree cannot be hidden behind an interpolated remainder: the queried
last-fold checks fail with overwhelming probability.

**Verification.** For each query, the verifier replays the transcript to obtain
the same `alpha_i` and the same query indices, then checks:

- every revealed pair authenticates under the committed root;
- each fold is consistent (fold of the layer-`i` pair at the queried position
  equals the layer-`(i+1)` value at that position);
- the final fold equals the remainder polynomial evaluated at the final-layer
  point.

## Transcript (Fiat-Shamir) order

Prover and verifier must drive the `Channel` identically:

```
absorb preprocessed roots (one per column, if any)
absorb trace roots (one per column)
sample alpha_col[j] and alpha_rel[r]        // lookup challenges (if any)
absorb accumulator roots (one per relation, if any)
sample alpha_k                              // transition weights (+ cyclic LogUp)
sample beta_k                               // boundary weights
absorb quotient root
sample z
absorb deep_evals                           // length 2*m_total+1
sample gamma_j                              // DEEP weights
[FRI] absorb root_i, sample alpha_i (per layer)
[FRI] absorb remainder
[FRI] sample query indices
```

## Parameters

`StarkParams` defaults:

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `trace_log` | — | `n = 2^trace_log` trace rows |
| `log_blowup` | `3` | `N = 2^(trace_log + log_blowup)` domain points |
| `num_queries` | `16` | query count |
| `remainder_log` | `3` | final FRI layer size `2^remainder_log` |

`FRI_OFFSET = 1 + i` in `QM31`.
