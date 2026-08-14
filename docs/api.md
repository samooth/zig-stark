# API Reference

This is a consumer-facing guide to the public surface of `zig-stark`: how to
depend on the library, the two protocol entry points (M31 DEEP-FRI STARK and
the Binius zero-check STARK), the committed-MLE PCS backends, the fields, and
the Binius gadgets. For the mathematical protocol details see
[`protocol.md`](protocol.md) and [`binius.md`](binius.md); for full worked
examples see [`examples.md`](examples.md).

## Using zig-stark as a library

Add it as a dependency and import the `zig-stark` module:

```zig
// build.zig.zon (in YOUR project)
.{
    .name = .my_proj,
    .version = "0.1.0",
    .fingerprint = 0x...,
    .minimum_zig_version = "0.16.0",
    .dependencies = .{
        .zig_stark = .{
            .url = "https://github.com/samooth/zig-stark/archive/<commit>.tar.gz",
            .hash = "<hash from zig build after first fetch>",
        },
        // or point at a local checkout:
        // .zig_stark = .{ .path = "../zig-stark" },
    },
    .paths = .{ "build.zig", "build.zig.zon", "src" },
}

// build.zig
const zig_stark = b.dependency("zig_stark", .{ .target = target, .optimize = optimize });
const my_exe = b.addExecutable(.{
    .name = "my-prover",
    .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .imports = &.{ .{ .name = "zig-stark", .module = zig_stark.module("zig-stark") } },
    }),
});
```

Then in your code:

```zig
const zig_stark = @import("zig-stark");
const binius = zig_stark.binius;   // binary-field stack
const stark = zig_stark.stark;     // M31 DEEP-FRI STARK (GenericStark)
const hash = zig_stark.hash;       // Blake3 (Hash.Digest = [32]u8)
```

The module namespace (`src/root.zig`) re-exports:

- `core` — `hash`, `merkle`, `channel` (Fiat-Shamir), `serialization`, `simd`, `bit_utils`.
- `m31`/`cm31`/`qm31` — the field tower types and their arithmetic.
- `circle_point`, `circle_domain`, `circle_coset`, `ntt_classic`, `ntt_simd`,
  `ntt_circle` — circle geometry and NTTs.
- `air_air`, `air_trace`, `air_frame`, `air_constraint` — AIR abstractions.
- `univariate`, `fri`, `stark`, `hash`, `merkle`, `channel` — the M31 protocol stack.
- `binius` — the whole binary-field stack (see below).

## M31 DEEP-FRI STARK

The entry point is `stark.GenericStark(Air)` for any `Air` implementing the
interface described in [`examples.md`](examples.md) §"Writing your own AIR"
(`num_columns`, `num_transition_constraints`, `num_boundary`, `PublicInputs`,
`evalTransition`, `boundaryAssertions`, `maxConstraintDegree`, plus optional
LogUp lookup metadata).

```zig
const Stark = zig_stark.stark.GenericStark(MyAir);
const params = zig_stark.stark.StarkParams{
    .trace_log = 8,        // trace length 2^trace_log
    .log_blowup = 3,       // FRI rate 2^-3
    .num_queries = 16,     // FRI query count
    .remainder_log = 3,
};

var pchan = zig_stark.channel.Channel.init("my-air:example");
var proof = try Stark.prove(alloc, params, .{ .claimed = ... }, trace, &pchan);
defer proof.deinit();                       // proof owns its memory

var vchan = zig_stark.channel.Channel.init("my-air:example"); // same domain!
const ok = try Stark.verify(alloc, params, .{ .claimed = ... }, &proof, &vchan);
```

- `Proof` owns its memory; release with `deinit()` (no allocator argument).
- `verify` never frees the proof; a rejected proof is still `deinit`ed by the caller.
- The channel domain separator must match between prover and verifier.
- The built-in `stark.FibAir` is used by the tests/examples as a reference AIR.

## Binius zero-check STARK

Three constructor families, all running the same protocol over a base field `F`
and extension field `E` (`E = F` is the single-field setting):

| Constructor | PCS | Proof size |
|-------------|-----|-----------|
| `binius.stark.BiniusStark(F, E)` | `CommittedMlePcs` (open all 2^k entries) | O(2^k) |
| `binius.stark.BiniusStarkWith(F, E, CP)` | any `CP` | — |
| `binius.stark.BiniusStarkFri(F, E, log_blowup, q)` | batched FRI-Binius | O(polylog) |

```zig
const F = zig_stark.binius.tower.Gf256;
const E = zig_stark.binius.tower.Gf2_128;
const Stark = zig_stark.binius.stark.BiniusStark(F, E);

// constraints: monomials over witness columns (see the gadgets below)
const constraints: [n]Stark.Constraint = ...;    // one per hypercube equation
const pins: [p]Stark.Pin = ...;                  // public boundary evaluations

// columns[c] has 2^k entries; the prover commits and sum-checks them
var proof = try Stark.prove(alloc, k, &columns, &constraints, &pins, "domain");
defer proof.deinit(alloc);

var roots: [num_columns]zig_stark.hash.Hash.Digest = undefined;
for (0..num_columns) |c| {
    var tree = try binius.pcs.CommittedMlePcs(F, E).commit(alloc, columns[c]);
    roots[c] = tree.root();
}
const ok = try Stark.verify(alloc, k, &roots, &constraints, &pins, proof, "domain");
```

Key types (`Stark.Constraint`, `Stark.Monomial`, `Stark.Pin`, `Stark.Proof`) are
defined on each instantiation. `Proof` owns its memory and is released with
`deinit(alloc)` using the allocator passed to `prove`.

## Committed-MLE PCS backends

Each backend exposes the same shape: `commit(alloc, table) !MerkleTree`,
`proveEval(alloc, k, table, r) !Proof`, `verifyEval(alloc, root, k, r, proof) !bool`.

- `binius.pcs.CommittedMlePcs(F, E)` — opens every hypercube entry (O(2^k)).
- `binius.fripcs.FriPcs(F, E, log_blowup, q)` — polylog FRI-Binius PCS.
- `binius.batchpcs.BatchFriPcsStark(F, E, log_blowup, q)` — batched eval PCS
  (one shared Merkle tree per FRI layer); this is what `BiniusStarkFri` uses.
- `binius.packed_pcs.PackedPcs(F, E)` — row packing + column Merkle tree, with
  `PackedPcsStark(F, E, config)` as the drop-in STARK adapter.

## Binius gadgets

Gadgets are comptime-parameterized types with the shape shown in
[`examples.md`](examples.md) §"Writing a custom Binius gadget". Each exposes
`num_columns`, `num_constraints`, `constraints`, a `generateWitness` builder, a
`freeWitness`/`result` pair, and `colX(...)` column accessors:

| Gadget | Purpose |
|--------|---------|
| `binius.adder.Adder(F, E)` | batch of 4-bit additions (ripple carry) |
| `binius.bitpack.BitPack(F, E)` | `num_bits` boolean columns + packed value |
| `binius.rangecheck.RangeCheck(F, E, m)` | value fits in `[0, 2^m)` |
| `binius.compare.Compare(F, E, m)` | `<` / `≤` / `>` / `≥` / `==` on two `m`-bit values |
| `binius.constraints.Builder` / `shiftInto` | compose gadgets into one proof |

`AdderWith`, `BitPackWith`, `RangeCheckWith` (and the `With` variants in
general) swap in a custom PCS `CP`. `BiniusArg(F, E)` / `BiniusArgWith(F, E, CP)`
/ `BiniusArgFri(F, E, log_blowup, q)` prove a hypercube product-sum instead of a
zero-check.

## Fields

- M31 tower: `m31.M31`, `cm31.CM31`, `qm31.QM31` (with SIMD helpers).
- Binius tower (`binius.tower`): `Gf2`, `Gf4`, `Gf16`, `Gf256`, `Gf2_32`,
  `Gf2_64`, `Gf2_128 = TowerField(7)`. Every tower element has `SIZE`,
  `toBytes(&[SIZE]u8)`, `fromBytes([SIZE]u8)`, `zero`, `one`, `add`, `mul`,
  `inv`, `fromInt`.
- Script fields (`binius.field`): `Gf16`, `Gf256` — note `field.Gf16` is 1 byte
  while `tower.Gf16` is 2 bytes; pick one per protocol instance.

## Hash, serialization, channel

- `hash.Hash.hashBytes([]const u8) [32]u8`, `Hash.hash2(a, b)`, `Hash.Digest`.
- `serialization.serialize(alloc, value) ![]u8` and
  `serialization.deserialize(alloc, bytes, T) !T` give every proof type a
  canonical little-endian wire format (see [`wire.md`](wire.md)).
- `channel.Channel.init(domain_separator)` with `absorbBytes`, `absorbDigest`,
  `absorb(value)`, `sample(T)`, `sampleBytes` — the unified Fiat-Shamir
  transcript for both stacks.
