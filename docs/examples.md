# Examples

Two end-to-end STARK proofs ship with the repository. Both follow the same
shape: generate a valid execution trace, run the prover, run the verifier, and
confirm that a forged claim is rejected.

Build and run:

```sh
zig build
./zig-out/bin/fibonacci
./zig-out/bin/ml_linear
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

## Rescue

`examples/rescue/src/main.zig` is a placeholder for a STARK over the Rescue
permutation. It currently prints `(TODO)`.
