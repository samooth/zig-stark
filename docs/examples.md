# Examples

Three end-to-end STARK proofs ship with the repository. All follow the same
shape: generate a valid execution trace, run the prover, run the verifier, and
confirm that a forged claim is rejected.

Build and run:

```sh
zig build
./zig-out/bin/fibonacci
./zig-out/bin/ml_linear
./zig-out/bin/rescue
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
accordingly (see `src/stark/stark.zig`).

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
