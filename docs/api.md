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

**Parallel prover.** `Stark.proveParallel(alloc, k, columns, constraints, pins,
public_inputs, &pool)` runs the per-column commitments, the combined zero-check
sum-check rounds, and the per-column eval openings across a
`core.pool.Pool` (a fork-join executor over `std.Thread`; a no-op when
`builtin.single_threaded`, so the same code compiles for wasm). The allocator
must be thread-safe during the joined sections (`std.heap.DebugAllocator` and
`std.heap.smp_allocator` are). The pool is created once and reused:
`var pool = core.pool.Pool.init(std.Thread.getCpuCount() catch 4);`.

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

## C ABI and the JavaScript / WebAssembly binding

`src/capi.zig` (header `zig-capi.h`) exposes the Binius STARK over the
serialized wire format for hosts that can't use Zig comptime types: a fixed
`Gf256` / `Gf2_128` / `CommittedMlePcs` instantiation with `zs_binius_prove`,
`zs_binius_verify`, `zs_binius_commit_wm`-style helpers and a host-supplied
allocator. `zig build wasm` emits a `wasm32-freestanding` module (~64 KB
ReleaseSmall) that imports `zig_stark_malloc` / `zig_stark_free` from the host.

`bindings/js/` wraps that module for Node.js and browsers:

```js
import { readFileSync } from 'node:fs';
import loadZigStark from './bindings/js/index.mjs';

const zs = await loadZigStark(readFileSync('bindings/js/zig_stark_capi.wasm'));
console.log(zs.version());

const k = 3;                                     // 2^k hypercube points
const column = new Uint8Array([0, 1, 0, 1, 1, 0, 1, 0]);
// w + w² = 0 everywhere (w is boolean)
const constraints = [{ terms: [
  { coeff: 1, factors: [0] },
  { coeff: 1, factors: [0, 0] },
] }];

const { proof, roots } = zs.proveColumns({ k, columns: [column], constraints });
const ok = zs.verify({ k, roots, constraints, proof });   // true
```

The wrapper ships ESM (`index.mjs`), CommonJS (`index.cjs`), and types
(`index.d.ts`); `zig_stark_capi.wasm` is regenerated by `zig build wasm` and
refreshed into `bindings/js/`. The statement format (columns / constraints /
pins) is the wire format documented in [`wire.md`](wire.md) and `zig-capi.h`.
The JS-side allocator is a monotonic bump over the exported linear memory, so
each module instance grows; for long-running processes re-instantiate the
module or provide a reclaiming allocator. In the browser, run one module
instance per **Web Worker** to parallelize provers without
`SharedArrayBuffer`.

**Native N-API addon (Node.js).** `bindings/node/addon.zig` exposes the same
API as the wasm binding but as a native `.node` addon (native speed, and the
optional `proveParallel` pool is available on the Zig side):

```sh
zig build node-addon -Doptimize=ReleaseFast \
  -Dnapi-include=$HOME/.nvm/versions/node/v24.14.0/include/node
```

```js
const addon = require('./zig-out/lib/addon.node');
const { proof, roots } = addon.proveColumns(k, cols, cons, pins, '');
const ok = addon.verify(k, roots, cons, pins, proof, ''); // true
```

Inputs are the same serialized wire-format buffers as `bindings/js/`
(`encodeColumns` / `encodeConstraints` / `encodePins`), so the same
statement-building code drives either backend. `proveColumns` returns
`{ proof: Buffer, roots: Buffer }`; `verify` returns a boolean. A smoke test
lives in `bindings/node/test/smoke.mjs`.

## CUDA (experimental, native server)

`src/cuda/` is the start of native GPU acceleration (server-side; browsers
stay on CPU + Web Workers). Zig 0.16 cannot emit CUDA kernels itself — the
nvptx LLVM backend errors and the self-hosted backend is unavailable — so
kernels are CUDA C compiled to PTX by `nvcc` and loaded at runtime via the
**CUDA Driver API** (`cuModuleLoadData` / `cuLaunchKernel`), with manual
`extern "c"` bindings in `src/cuda/cuda.zig` (`@cImport("cuda.h")` mislinks
the Driver API on 0.16). The PTX is embedded via `@embedFile` (no runtime
file), and `Cuda.init` fails cleanly when there is no GPU/driver so callers
fall back to CPU.

- `zig build cuda-hello` — build + run the `vecAdd` validation kernel
  (requires a GPU + driver; on the RTX 3080 it processes 1M u32 in ~3 ms
  including transfers).
- `zig build cuda-gf` — Gf256 field-mul kernel: bit-exactness vs the CPU
  tower over 2^20 samples.
- `zig build cuda-sumcheck` — Gf256 and Gf2_128 sum-check rounds on the GPU:
  per-round `values[t]` bit-exact with CPU, full `BiniusStark(Gf256,Gf256)`
  and `BiniusStark(Gf16,Gf2_128)` proofs byte-identical to the CPU ones, plus
  a benchmark.
- `zig build cuda-circlefft` — M31 circle FFT on the GPU: forward + inverse
  bit-exact with `ntt/circle.zig` for n = 8..65536 (`canonicHalf` sizes), plus
  a CPU-vs-GPU timing at the largest size. `src/cuda/circlefft_gpu.zig` builds
  the twiddle tree with the library's own `precomputeTwiddles`/`circleTwiddles`
  (now exported from `ntt_circle`) so every twiddle matches the CPU exactly and
  only the per-layer butterfly, bit-reversal and (de)interleave kernels
  (`src/cuda/kernels/circlefft.cu`) run on the GPU. Sizes below lg = 3 and
  missing GPUs fall back to the CPU transform.
- `zig build cuda-kernels` — regenerate `src/cuda/kernels/*.ptx` with `nvcc`
  (the committed PTX keeps the default build free of the CUDA toolkit).

The library itself stays CUDA-free: the Binius sum-check reads a pluggable
accelerator hook, `src/binius/accel.zig` (exported from `binius.accel`). A
CUDA-enabled host calls `src/cuda/sumcheck_gpu.zig`'s `enable()`, which
registers the `gf256_values`/`gf128_values` evaluators; `accel.mode`
(`GpuMode` `auto`/`on`/`off`, default `auto`) controls whether the prover may
use them — `auto` falls back to CPU when no hook is registered, `on` errors
with `error.GpuUnavailable`, `off` never touches the GPU. This is E1 of the
GPU roadmap (Gf256 then Gf2_128 bit-sliced field mul). E2 (landed) is the M31
circle FFT via `src/cuda/circlefft_gpu.zig`; E3 will be Merkle (Blake3)
hashing.
