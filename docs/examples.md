# Examples

Five end-to-end STARK proofs ship with the repository. All follow the same
shape: generate a valid execution trace, run the prover, run the verifier, and
confirm that a forged claim is rejected.

Build and run:

```sh
zig build
./zig-out/bin/fibonacci
./zig-out/bin/ml_linear
./zig-out/bin/rescue
./zig-out/bin/binius_adder
./zig-out/bin/binius_bitpack
```

## Fibonacci

`examples/fibonacci/src/main.zig`

The AIR has two columns `(a, b)` holding consecutive Fibonacci numbers:

```
a_{i+1} = b_i
b_{i+1} = a_i + b_i
```

with boundary assertions

```
a_0 = 0        fib(0) = 0
b_0 = 1        fib(1) = 1
a_{n-1} = y    fib(n) = y   (the public claim)
```

The transition is *time-homogeneous* (the same relation at every row), so it is
expressed directly in terms of the frame `(current, next)`.

Running it with `trace_log = 8` proves a claim about `fib(256)`:

```
trace length: 256
verifier accepted proof: true
claimed fib(n) matches direct computation
```

## Linear ML layer

`examples/ml_linear/src/main.zig`

A single linear layer of a neural network:

```
y = w . x
```

where `w` is a fixed weight vector (a constant in the AIR) and `x` is a public
input vector. The trace is a single accumulator column of length `n = w.len`:

```
acc[r] = sum_{l <= r} w_l * x_l
```

with boundary assertions `acc[0] = w_0 * x_0` and `acc[n-1] = y_claimed`.

Because each row adds a *different* increment, this AIR needs the
row-dependence machinery: the transition is

```
C(x) = acc(w*x) - acc(x) - inc(x)
```

where `inc(x)` is the polynomial interpolating the increments
`r -> w_{r+1} * x_{r+1}` over the trace subgroup `H`. Evaluating `C` on `H`
gives exactly `acc[r+1] - acc[r] - w_{r+1} x_{r+1}`, so `C` vanishes on
`H \ {w^(n-1)}` exactly when the accumulator follows the recurrence. This is
what the evaluation-point argument of `evalTransition(x, current, next, out)`
is for.

Running it with `n = 8`:

```
inputs:        1 2 3 4 5 6 7 8
weights:       1 2 3 4 5 6 7 8
claimed y:     204
verifier accepted proof: true
verifier rejected forged claim: true
claim matches direct computation
```

## Writing your own AIR

To prove a new computation, define a struct implementing the AIR interface used
by `stark.GenericStark`:

```zig
const MyAir = struct {
    pub const num_columns = 2;
    pub const num_transition_constraints = 1;
    pub const num_boundary = 2;

    pub const PublicInputs = struct {
        claimed: QM31,
    };

    pub fn evalTransition(x: QM31, current: []const QM31, next: []const QM31, out: []QM31) void {
        _ = x; // ignore unless the constraint is row-dependent
        out[0] = next[0].sub(current[0]).sub(current[1]);
    }

    pub fn boundaryAssertions(public: PublicInputs, n: usize, out: []stark.BoundaryAssertion) void {
        out[0] = .{ .column = 0, .step = 0, .value = QM31.zero() };
        out[1] = .{ .column = 0, .step = n - 1, .value = public.claimed };
    }
};
```

Then prove and verify:

```zig
const Stark = stark.GenericStark(MyAir);
const trace = try MyAir.generateTrace(alloc, ...); // you provide this
var pchan = channel.Channel.init("my-air:example");
var proof = try Stark.prove(alloc, params, .{ .claimed = ... }, trace, &pchan);
defer proof.deinit();
var vchan = channel.Channel.init("my-air:example");
const ok = try Stark.verify(alloc, params, .{ .claimed = ... }, &proof, &vchan);
```

Key requirements:

- the trace is a list of `num_columns` column slices, each of length `2^trace_log`;
- the domain separator of the prover's and verifier's channels must match;
- the transition constraints must vanish on `H` (the trace rows) for a valid
  trace; the composition multiplies them by `(x - w^(n-1))` so the last row is
  exempt;
- boundary assertions pin specific rows to public values; the verifier uses them
  both to rebuild the composition and to replay the transcript.

## AIRs with lookups (preprocessed columns)

To add a LogUp lookup relation to an AIR, declare the preprocessed and lookup
metadata and pass the table columns to `proveWithPreprocessed` instead of
`prove`:

```zig
const MyLookupAir = struct {
    pub const num_columns = 3; // e.g. [value, mult, selector]
    pub const num_preprocessed = 1; // [table]
    pub const num_transition_constraints = 0;
    pub const num_boundary = 0;

    // One relation: the combined key of the selector row must appear in the
    // table with the given multiplicity.
    pub const num_lookup_columns = 1;
    pub const num_lookup_relations = 1;
    pub const lookup_selector_columns = [1]usize{2};
    pub const lookup_key_columns = [1][]const usize{&.{0}};
    pub const lookup_table_columns = [1][]const usize{&.{0}};
    pub const lookup_multiplicity_columns = [1]usize{1};
    // ... evalTransition / boundaryAssertions / maxConstraintDegree as usual ...
};
```

Prove with both the trace and the preprocessed table:

```zig
const Stark = stark.GenericStark(MyLookupAir);
var proof = try Stark.proveWithPreprocessed(
    alloc, params, .{}, table, trace, &pchan,
);
```

Requirements specific to lookup AIRs:

- `num_lookup_relations > 0` implies `num_preprocessed > 0` and
  `num_lookup_columns > 0`, and the AIR must declare
  `lookup_selector_columns`, `lookup_key_columns`, `lookup_table_columns` and
  `lookup_multiplicity_columns` (per relation).
- The honest trace must *interleave* the lookup rows (selector = 1) and the
  table rows (selector = 0); the LogUp running-sum argument is cyclic, so the
  multiset of lookup keys (weighted by multiplicity) must equal the multiset of
  table entries across the whole trace.
- The accumulator column is appended internally at index `num_columns + r`; a
  boundary assertion `acc[0] = 0` is added automatically.

See [`protocol.md`](protocol.md) for the LogUp protocol details and the exact
transcript order.

## Rescue

`examples/rescue/src/main.zig` proves the correct evaluation of a Rescue
permutation: a permutation over a 4-element QM31 state (`s = 4`) with
`n - 1 = 7` rounds. The AIR has four columns (one per state element), four
transition constraints and eight boundary assertions.

The Rescue sbox is `x^5`, so the transition constraints are degree-5 polynomials
in the columns — this is the motivating example for the AIR-level
`maxConstraintDegree(n)`: as polynomials in the evaluation point `x` the
constraints have degree `5 * (n - 1)`, which is far above the `n - 1` degree of
the trace columns, and the FRI commitment for the DEEP combination must be sized
accordingly (see `src/m31/stark.zig`).

The round constants depend on the row, so they are interpolated over the trace
subgroup `H` and evaluated through `x` inside `evalTransition`. Only the forward
sbox is used — the M31 inverse sbox `x -> x^(1/5)` is a high-degree polynomial
that cannot appear in a low-degree constraint. The round-constant polynomials
are shared between prover and verifier via `RescueAir.prepare` (called before
`prove`/`verify`), and `num_rounds = n - 1` rounds are applied to the public
`initial` state to obtain the claimed `final` state.

Running it with `n = 8`:

```
initial state:  1 2 3 4
final state:    1620044097 654387451 611328641 1042552547
verifier accepted proof: true
verifier rejected forged final state: true
claim matches direct round computation
```

## Binius 4-bit adder

`examples/binius_adder/src/main.zig`

This one exercises the *other* stack (`src/binius`): a zero-check STARK over a
binary tower field instead of the M31 DEEP-FRI construction. A batch of `2^k`
independent 4-bit additions `x + y = s` is proved with one 4-bit ripple-carry
adder gadget (`src/binius/adder.zig`). The witness has 16 bit-sliced columns
(`a_0..a_3, b_0..b_3, s_0..s_3, c_1..c_4`) and 16 pointwise constraints: 8
booleanity, 4 full-adder sum, and 4 carry equations.

The gadget runs over the witness field `F = Gf256` with the protocol lifted to
the extension field `E = Gf2_128` (`BiniusStark(F, E)`), so Schwartz-Zippel
soundness stays ≈ 2^-128 even though `F` is a small byte field. Boundary pins
make the first instance's five output bits (`s_0..s_3, c_4`) a public statement:
they are folded into the zero-check and re-sampled as challenges, so the
verifier does not trust the witness for the claimed result.

The example demonstrates the failure modes: a tampered commitment root is
rejected, a re-proved witness that violates the sum constraint at every point is
rejected, and altering the public input string or a pin value re-derives
different Fiat-Shamir challenges and is rejected. It also prints the proof-size
breakdown, where the eval openings dominate because the default PCS
(`CommittedMlePcs`) opens every one of the `2^k` hypercube entries per column —
the motivation for the sub-linear `FriPcs` layer in `src/binius/fripcs.zig`.

Running it (`k = 4`, 16 additions, Debug build):

```
binius 4-bit ripple-carry adder batch (16 additions, k=4)
  columns:    16
  constraints:16 (+5 boundary pins)
  prove:      73411.22 ms
  verify:     2422.58 ms
  verifier accepted proof: true
  x0 + y0 = 5 + 2 = 7; pinned as a boundary assertion
  sumcheck:   640 B
  eval opens: 33024 B (16 columns x 16 entries)
  verifier rejected tampered commitment: true
  verifier rejected forged witness: true
  verifier rejected altered public input: true
  verifier rejected altered boundary pin: true
```

## Binius bit-pack gadget

`examples/binius_bitpack/src/main.zig`

A batch of `2^k` independent `num_bits`-wide values is proved to be a valid
bit decomposition of its packed field elements. The witness (`src/binius/
bitpack.zig`) has `num_bits` boolean bit columns plus one packed value column,
and `num_bits + 1` pointwise constraints: `num_bits` booleanity equations
`b_i + b_i² = 0` and one pack equation `v = Σ_i b_i·e_i` with `e_i =
fromInt(1<<i)`.

Because a binary tower field's bit string *is* the coefficient vector in the
standard basis, the pack equation is a field identity: a committed value is
exactly the integer encoded by its bit columns. This is the primitive behind
range checks and bit manipulation — any assertion "`x` is a valid `uN` whose
bits are `b`" is `pack + booleanity`, so a verifier can commit to the bit
columns and enforce the numeric value.

The example runs over `F = Gf256` (`num_bits = 8`) with `E = Gf2_128`, pins
the first instance's packed value as a public statement, and demonstrates the
same failure modes as the adder (tampered commitment, forged witness, altered
public input, altered pin).

Running it (`k = 4`, 16 values, Debug build):

```
binius bit-pack gadget batch (16 values, k=4, 8-bit)
  columns:    9
  constraints:9 (+1 boundary pins)
  prove:      224.15 ms
  verify:     14.46 ms
  verifier accepted proof: true
  v0 = 7; pinned as a boundary assertion
  sumcheck:   640 B
  eval opens: 18576 B (9 columns x 16 entries)
  verifier rejected tampered commitment: true
  verifier rejected forged witness: true
  verifier rejected altered public input: true
  verifier rejected altered boundary pin: true
```

## Writing a custom Binius gadget

The adder and bit-pack gadgets are the two reference implementations of the
`BiniusStarkWith` interface. A gadget is a struct type with four pieces:

```zig
const MyGadget = struct {
    // 1. Shape: one column per witness polynomial, one constraint per equation.
    pub const num_columns = 2;
    pub const num_constraints = 1;

    // 2. Monomials with scalar coefficients in F and column indices as factors.
    pub const constraints: [num_constraints]Stark.Constraint = [_]Stark.Constraint{
        .{ .terms = &.{
            .{ .coeff = F.one(), .factors = &.{0} },
            .{ .coeff = F.fromInt(2), .factors = &.{1} },
        } },
    };

    // 3. A witness builder (any signature you like).
    pub fn generateWitness(allocator, ...) ![num_columns][]F { ... }

    // 4. A column-slice accessor, so the verifier can index the right column.
    pub fn colX(c: usize) usize { ... }
};
```

The constraint is enforced at every hypercube point: the prover commits each
column with the PCS, the sumcheck folds the constraints into one zero-check,
and Fiat-Shamir challenges bind roots, pins, and the constraint choice. Only
field arithmetic on the *monomial product* is performed, so any equation that
is a polynomial identity over `F` can be expressed; the one requirement is
that scalar coefficients live in `F`, not `E` (the protocol's linear
combination is over `E`).

How to choose between the layers:

| You need...                          | Use                               | Interface                     |
|--------------------------------------|-----------------------------------|-------------------------------|
| Custom zero-check gadget over a tower field | `BiniusStarkWith(F, E, CP)` | `stark.zig`            |
| Gadget with default PCS (eval-open every point) | `BiniusStark(F, E)` | `stark.zig`       |
| Proofs with sub-linear openings (additive FRI) | `BiniusStarkFri(F, E, log_blowup, q)` | `stark.zig` |
| A product-sum argument over `Gf2_128` | `BiniusArg(F, E)` (and `*Fri`, `*With`) | `arg.zig` |
| Plug in any committed MLE PCS       | `CommittedMlePcs` / `FriPcs`      | `pcs.zig` / `fripcs.zig`      |

`BiniusArg` and `BiniusStark` are distinct protocols: the argument (`arg.zig`)
proves a *sum* over the hypercube of a rational product, while the STARK
(`stark.zig`) proves a *zero-check* (the constraint polynomials vanish at
every point). Both build on the same field, sumcheck, and PCS layers. See
[`binius.md`](binius.md) for the protocol-level differences and the memory
model. The `*With` variants are the canonical interface — `BiniusStark(F, E)`
is `BiniusStarkWith(F, E, CommittedMlePcs(F, E))` — so any of the three PCS
backends can be swapped in without touching gadget code.
