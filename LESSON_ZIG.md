# LESSON_ZIG.md

Session notes on Zig itself, gathered while porting the stwo circle FFT to Zig and
adding benchmarks/tests. Focused on the quirks of the exact toolchain in use
(0.16.0-dev), not generic Zig 101.

## Toolchain & build system

- The project's Zig is a 0.16.0-dev build (pre-release). Several std APIs differ
  from 0.14/0.15 (see "std.time" and "Format strings" below). Always check the
  actual std in `zig env` / the std lib before assuming an API exists.
- Build API: modules are declared with `b.addModule`; per-artifact modules with
  `b.createModule(.{ .root_source_file = ..., .target, .optimize, .imports })`.
  Executables/tests use `b.addExecutable` / `b.addTest` + `b.addRunArtifact`.
- A shared `lib` module (`src/root.zig`) is imported by tests, examples and
  benchmarks via `.imports = &.{ .{ .name = "zig-stark", .module = lib } }`.
  Top-level `pub const` re-exports in `root.zig` are the import surface.
- Formatting is wired as a *check* step: `b.addFmt(.{ .paths = &.{"."}, .check = true })`
  under a `fmt` step. Run locally with `zig build fmt`. The author's convention:
  `zig fmt` on edited files, then `zig build fmt` + `zig build test` before commit.

## Import path restriction (module path)

- `@import` can only reference files reachable from the module root. A throwaway
  file placed outside the repo cannot import project sources by absolute path:
  `error: import of file outside module path`. Put cross-check/test scratch files
  inside the repo tree instead (or use the module's exported names).

## std.time has no Timer / Instant

- In this 0.16.0-dev, `std.time` contains only `epoch` and the `ns_per_*` /
  `us_per_*` / `ms_per_*` constants — `std.time.Timer` and `Instant` are gone
  (moved to the new async `std.Io` layer).
- Fallback used for the benchmark: Linux monotonic clock directly:
  `std.os.linux.clock_gettime(.MONOTONIC, &ts)` with `std.posix.timespec`.
- Gotcha: in this build `timespec` fields are named `.sec` / `.nsec` (not
  `tv_sec` / `tv_nsec`), and the clock id enum is `std.posix.CLOCK` (re-exported
  from the OS layer) with `MONOTONIC` etc.
- `now()` helper that worked:

  ```zig
  fn now() i128 {
      var ts: std.posix.timespec = undefined;
      _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
      return @as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec));
  }
  ```

## Integer / type-cast gotchas

- `M31.fromInt(x)` takes `u32`, not `usize`. Passing a `usize` (e.g. transform
  length) is a compile error ("cannot represent all possible 64-bit values");
  cast explicitly: `M31.fromInt(@intCast(n))`.
- Shift amounts are `u6`: `h << @as(u6, @intCast(i + 1))`. Using `usize` directly
  fails to coerce.
- `std.math.log2_int(usize, n)` exists and returns the log width — used to derive
  transform log-size from a slice length.
- Unused local variables are hard errors in this Zig; remove them rather than
  keeping dead `const half = n / 2;` lines.

## Format strings

- There is no `f` specifier suffix: `{d:>7.1f}x` is `error: extraneous trailing
  character 'f'`. Fixed-point floats use precision only: `{d:.1}`.
- Width + alignment work for ints/strings (`{d:>9}`, `{s:>11}`) but combining
  width with float precision can be unreliable; keep floats as plain `{d:.1}`.

## Idioms that worked well

- Per-scope `defer`: `defer alloc.free(buf)` inside a `while` loop frees each
  iteration's buffer automatically (defers attach to the enclosing scope).
- In-place swaps: `std.mem.swap(M31, &vals[i], &vals[j])`.
- Slice copy: `@memcpy(dst, src)`.
- Tests use `std.testing.allocator` (catches leaks) + `std.testing.expect`,
  `expectEqual`. `lib.zig` uses `std.testing.refAllDecls(@This())` so every
  exported decl's tests run under `zig build test`.
- General purpose allocator in executables: `var gpa = std.heap.GeneralPurposeAllocator(.{}){}; const alloc = gpa.allocator();`.
- For a bench harness, time-budgeted iteration counts (measure one pass, then
  run `max(1, budget / one)` iterations) keep every size's timing in a stable
  range instead of guessing a fixed iteration count.

## Process lessons

- Before porting a nontrivial numeric algorithm, validate a reference
  implementation in Python (or similar) first; port after it is green.
- Cross-check the port against the reference on a fixed input (not just
  self-consistency): both an FFT and its "reference" can share the same bug.
  Comparing a concrete input/output byte-for-byte caught one such error.
- Sign commits with `git commit -S`; verify with `git log --show-signature -1`.
- Keep temporary reference clones out of git (`.tmp/` added to `.gitignore`).

## 0.16.0-dev std gotchas (Additive FRI session)

- `std.ArrayList` has no `init(allocator)` in this build; the type only exposes `empty`,
  `initCapacity`, `initBuffer`. When the element count is known up front (FRI layers,
  alphas, queries) prefer a plain `allocator.alloc` slice over an ArrayList entirely.
- `[32]u8` (e.g. `Hash.Digest`) does not support `==` / `!=`; compare with
  `std.mem.eql(u8, &a, &b)`.
- Tower field `zero()` / `one()` are functions, not constants: `Gf256.one` (no
  parentheses) has type `fn () T` and only errors at the call site — keep the parens.
- `toBytes` writes into a caller buffer (`out: *[SIZE]u8`) rather than returning an
  array; `Hash.hash2` takes two `[32]u8` digests, not byte slices.
- A method with a value receiver auto-derefs when called through a pointer:
  `tree.open(pn, alloc)` on a `*MerkleTree` field works directly.
- `errdefer` over a partially filled slice must track a filled count: freeing
  `layers[0..L]` when only `[0..k]` were initialized is UB. Increment the count after
  each successful fill (the `committed` / `qbuilt` pattern).
- With `testing.allocator`, every allocation must be freed even on success paths: a
  `prove` helper that builds a codeword must free it after `proveCodeword` copies it, and
  the final folded FRI layer (used only for remainder interpolation, never committed)
  needs an explicit free.
- Random in tests: `rnd.uintLessThan(u32, bound)`, not `rnd.uint(u32)`.

## Unified Fiat-Shamir channel + comptime params (max_cols session)

- The binius STARK previously derived τ, α_t and the sum-check seed through four
  ad-hoc `Sha256.init` helpers (`seedForRoots`, `seedFor`, `challengePoint`,
  `combinationCoeffs`) that never absorbed public inputs. Replaced them all with
  the shared core `Channel` (Blake3, m31-style): absorb public-input bytes, then
  the roots; `sample(F)` τ and α_t; `sampleBytes(&seed)` to seed the nested
  sum-check transcript. One source of randomness, prover/verifier replay it
  verbatim, and public inputs are bound.
- To expose the channel state for seeding a nested transcript, `sampleBytes`
  was promoted from private to `pub` on the core `Channel`; it already absorbs
  the derived bytes back (correct Fiat-Shamir), so later samples stay fresh.
- `BiniusStark(F)` and `BiniusArg(F)` became `BiniusStark(F, comptime max_cols)`
  and `BiniusArg(F, comptime max_tables)`: the 16-column cap is now a comptime
  parameter. Zig has no default type/param values, so every call site must pass
  it. The adder ties it to its own `num_columns` (`4 * num_bits`), so bumping the
  gadget width later grows the STARK cap automatically.
- Gotcha: a comptime struct const that is only used inside a helper becomes
  unused-if-dead — but `domain` (`Channel.init(domain)`) stays referenced, and
  tests read it via `BiniusStark(Gf256, 16).domain` without instantiating.
- The `sample(F)`-based challenges use each field's `fromBytes` (which masks to
  `BITS`), so the 4-bit-mask regression still holds: `fromInt` masks to 4/8 bits
  on `SIZE == 1` tower fields.

## Boundary pins (public assertions) session

- Pins are enforced in the same zero-check as user constraints: the indicator
  constraint `δ_p(x)·(w_col(x) + value) = 0` with `δ_p(x) = ∏_j (x_j + 1 + p_j)`,
  written as two monomials (`1·δ_p·w_col`, `value·δ_p`). The pin-kernel tables
  ℓ_j = x_j + 1 + p_j are public (never committed) and live in shared-table slots
  after the witness columns and the τ-kernel; both sides rebuild them from the
  pin points, so the verifier evaluates them at τ' without an opening.
- The pins are absorbed into the Fiat-Shamir channel (`col`, `point`, `value`)
  before the roots, so any pin change re-derives every challenge.
- Soundness of a single-point pin is `1 - (deg + 1)/|F|`-ish (the combined
  constraint R vanishes everywhere except the pinned point, so the zero-check
  catches it unless the combination coefficient α_p or β_τ(p) vanishes). Tests
  rely on the deterministic per-instance α/τ, exactly like the pre-existing
  "non-boolean witness is rejected" test.
- Allocator gotcha: never `return out[0..count]` and later `free` it. Freeing a
  slice whose `.len` differs from the allocation trips the debug allocator's
  size check ("Invalid free"). Allocate the exact count after a counting pass
  (see `distinctPoints`).
- The `errdefer`/`defer` tracked-count pair (free the `filled` prefix on both
  paths) is needed again for the pin-kernel table batch and the pin-constraint
  batch, same as the FRI layers.

## Extension-field (E) soundness session

- The binius PCS and STARK are now parameterized over (F, E):
  `MlePcs(F, E)`, `CommittedMlePcs(F, E)`, `BiniusStark(F, E, max_cols)`,
  `Adder(F, E)`; take `E = F` for the classic single-field setting. The witness,
  the Merkle leaves, and the commitments stay in `F`; τ, α_t, the sum-check
  round challenges, and the PCS query points live in `E`; base entries are
  lifted via `E.embed(F.LEVEL, x)` (zero-cost, identical bit string). Every
  Schwartz-Zippel application then carries ≈ 1/|E|, so a script-friendly
  GF(16)/GF(256) witness keeps ≈ 2^-128 soundness with `E = tower.Gf2_128`.
  Cost: all sum-check arithmetic runs in `E` (~100× slower than GF(256) in
  ReleaseFast, worse in Debug).
- `lift` on `MlePcs` only compiles for `F != E` when `F` is a *tower* field
  (has `LEVEL`); `field.zig`'s `BinaryField` has no `LEVEL` and a distinct bit
  representation, so it can only be used with `E = F` — extending it is a
  compile error, which is correct because embedding it into the tower is not
  bit-compatible.
- `seedFor` switched from packing `[128]u8` to a Blake3 digest: the raw pack
  truncated the bound point once `E` reached 128 bits and k grew (16·k > 128).
- Gotcha: `E.SIZE` is a `u8` (16 for Gf2_128), so
  `k * (dmax + 1) * E.SIZE` overflows `u8` in the example's proof-size
  estimate — cast the leading factors to `usize`.
- Debug builds over GF(2^128) are very slow (un-inlined recursive Karatsuba
  tower mul, ~3^7 base ops per mul); the adder example exceeds two minutes in
  Debug. Use ReleaseFast for extension-mode runs.



