# LESSON_ZIG.md

Session notes on Zig itself, gathered while porting the stwo circle FFT to Zig and
adding benchmarks/tests. Focused on the quirks of the exact toolchain in use
(Zig 0.16.0 stable, released 2026-04-13), not generic Zig 101.

## Toolchain & build system

- The project targets Zig 0.16.0 stable. It was developed against a 0.16.0-dev
  build; the compatibility pass (commit `2e3e0fc`) fixed the two API changes the
  stable release introduced: `std.heap.GeneralPurposeAllocator` (a dev-era alias
  for `DebugAllocator`) is gone, and the never-mutated check now fires on `Ntt`
  instances held in arena scopes and a test slice, so those are `const`. Several
  std APIs differ from 0.14/0.15 (see "std.time" and "Format strings" below).
  Always check the actual std in `zig env` / the std lib before assuming an API
  exists.
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

- In Zig 0.16.0 (stable and dev), `std.time` contains only `epoch` and the
  `ns_per_*` / `us_per_*` / `ms_per_*` constants — `std.time.Timer` and
  `Instant` are gone (moved to the new async `std.Io` layer).
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

## 0.16.0 std gotchas (Additive FRI session)

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

## Unified Fiat-Shamir channel (channel session)

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
- The `sample(F)`-based challenges use each field's `fromBytes` (which masks to
  `BITS`), so the 4-bit-mask regression still holds: `fromInt` masks to 4/8 bits
  on `SIZE == 1` tower fields.
- (Superseded in the runtime-caps session below: the comptime `max_cols` /
  `max_tables` parameters this section originally documented were later removed
  — the STARK and arg are `BiniusStark(F, E)` / `BiniusArg(F, E)` again.)

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
  `MlePcs(F, E)`, `CommittedMlePcs(F, E)`, `BiniusStark(F, E)`,
  `Adder(F, E)`, `BitPack(F, E)`; take `E = F` for the classic single-field
  setting. The witness,
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

## CLMUL / comptime-heavy code session (tower fast-multiply, §5)

- **Inline asm: `pclmulqdq` is a 2-operand instruction** (the destination XMM is
  also the first source) while `vpclmulqdq` is 3-operand but requires AVX. The
  non-VEX form worked with one `"+x"` output (preloaded with operand a) and one
  `"x"` input: `pclmulqdq $0x00, %[b], %[out]`. Gate on
  `builtin.cpu.has(.x86, .pclmul)` (this std uses `.pclmul`; `std.crypto.ghash_polyval`
  shows the `vpclmulqdq` variant with an extra `.avx` check).
- **u128 shifts need `u7` amounts.** `b >> i` with `i: u8` is a compile error
  ("expected type 'u7'"). But `while (i < 64)` / `while (i < 128)` loop counters
  of type `u6` / `u7` *overflow at the final increment* and panic at runtime —
  use a `u8` counter and `@intCast` each shift amount (bounds are loop-guaranteed).
- **`@inComptime()` routes hardware-only asm away from the comptime
  interpreter.** A `clmul64Auto` that returns the software fallback when
  `@inComptime()` is true lets comptime code reuse the same fast-path function
  without executing the `pclmulqdq` instruction in the compiler.
- **Heavy comptime table generation is a trap.** Precomputing the tower's
  fast-multiply tables at comptime (generator search = BITS recursive tower
  muls) exceeded `evaluation exceeded 16777216 backwards branches` and took
  ~90 s to fail. `@setEvalBranchQuota` just raises the ceiling; the interpreter
  is slow enough that generation should be moved to *runtime* lazy init (a few
  microseconds) instead. Prefer comptime only for small, cheap constants.
- **No `std.once` / `CallOnce` in this 0.16 std.** `std.atomic.Mutex` only has
  `tryLock` / `unlock` (no blocking `lock`): write a spin
  `while (!m.tryLock()) std.atomic.spinLoopHint();` plus an
  `std.atomic.Value(bool)` "ready" flag with acquire/release ordering for lazy
  init. Note the per-instantiation `var` at container scope inside the generic
  `TowerField(level)` struct gives one global per level.
- **Array-length arithmetic overflows narrow ints.** `[2 * BITS]u128` with
  `BITS: u8` (128) → `256` overflows `u8` at comptime. Cast to `usize`:
  `[2 * @as(usize, BITS)]u128`.
- **Anonymous struct field type inference can poison a `var`.** The `else`
  branch `.{ .lo = p, .hi = 0 }` infers `.hi` as `comptime_int`; the peer type
  of the whole `if` becomes that, and `var y = prod.hi;` then errors ("variable
  of type comptime_int must be const"). Annotate: `.hi = @as(u128, 0)`.
- **A `const` declared inside a `while` body is not visible after the loop.**
  Hoist `var g: Self = undefined;` above the search loop and assign inside.
- **Parameter names collide with struct members.** A parameter `inv` inside a
  struct that already has `pub fn inv` fails with "function parameter shadows
  declaration of 'inv'". Rename the parameter (`inv_out`).
- Generic recursion subtlety: a `mulRec` that recurses through the *subfield's*
  `mul` dispatcher keeps comptime use cheap, but a `mulRec` that calls its own
  level's fast path deadlocks on the lazy-init mutex — build tables at a level
  only via strictly-lower-level dispatches.

## Runtime caps session (drop comptime max_cols / max_tables)

- The comptime caps introduced in the channel session (`max_cols` /
  `max_tables`) made the STARK types depend on a fixed array bound and forced
  every call site to repeat the gadget's width. Removing them means every
  fixed-size array sized by the cap becomes a heap allocation at the *actual*
  count: roots, `seen`, `distinct`, `value_of` in `stark.zig`, roots in
  `arg.zig`. `BiniusStarkWith(F, E, CP)` is the canonical interface;
  `BiniusStark(F, E)` / `BiniusStarkFri(F, E, log_blowup, q)` are thin aliases.
- `seedForRoots` previously packed up to `max_tables * 32` bytes to hash; with
  the cap gone it streams through `Channel`/Blake3 incrementally instead
  (one `update` per root), so no `[N]u8` buffer sized by a cap is needed.
- Passing a comptime slice argument through many layers stays comptime at the
  call site but is easy to break: after removing the third type parameter, the
  remaining callers (adder example, e2e tests, benchmarks, in-module tests) all
  needed the trailing arg dropped — grep for `BiniusStark(`/`BiniusArg(` before
  and after.

## Memory model / caller-deinit session (leak sweep)

- **`errdefer` does NOT fire on `return null`.** The sum-check's `runRounds`
  had `errdefer allocator.free(challenges)` and `return null` when a round
  consistency check failed — that return skips errdefer, so every *rejected*
  proof (the normal path for a tampered root, which changes the transcript-seeded
  challenge) leaked `challenges`. Fix: free explicitly before the `return null`.
  When a function can fail with `?T`, never rely on `errdefer` for the null path.
- The caller-deinit convention: every public `Proof` owns its heap memory and
  exposes `deinit(self: *Proof, allocator)`; call with the *same* allocator as
  `prove`. A proof binding must be `var` for the deferred deinit (it takes
  `*Proof`): `var proof = try S.prove(alloc, ...); defer proof.deinit(alloc);`.
  `verify` never frees proof memory; a rejected proof still must be deinit'd.
- De-arenaring the test suite: dozens of tests wrapped bodies in
  `std.heap.ArenaAllocator` (which never leak-checks). Converting each to
  `std.testing.allocator` surfaced every missing free (proofs, Merkle trees,
  forged-witness copies, gadget witnesses) — the whole suite now runs under the
  leak-checking allocator.
- Test leak-fix pattern that kept recurring: a test committed its own columns
  with `CommittedPcs.commit` but never called `tree.deinit()`, and `Proof`
  types with a `self: *Proof` deinit forced the binding from `const` to `var`.
  `freeWitness`/`freeColumns` helpers exist so the gadget builder and its test
  share one free path.

## Bit-pack gadget session

- A `blk:` block uses `break :blk` / `break :inner`, **not** `return` —
  `'return' outside function scope` is the error when you write `return out;`
  inside the `const constraints = blk: { ... };`.
- A `var` inside a comptime `blk:` cannot be the address taken into a global:
  `error: global variable contains reference to comptime var`. Fix: wrap the
  mutable fill in an inner `blk:` that produces a `const` array
  (`const pack_terms = inner: { var tmp ...; break :inner tmp; };`), then
  `&pack_terms` is a stable global reference. The label must be renamed (the
  outer block already owns `blk`).
- Bit-width generic types: `std.meta.Int(.unsigned, F.BITS)` gives `u4`/`u8`/
  `u128` per field in one expression — the gadget's `UInt` stays in sync with
  the tower width without a separate `comptime intWidth`.
- `inline for (.{ Gf16, Gf256 }) |F|` lets one test body instantiate a generic
  gadget over two fields; each iteration is its own scope, so per-iteration
  `defer`s run at iteration end (no leaks between fields).
- `[n]T` array types need comptime `n`: a `const n = @as(usize, 1) << k` with
  comptime `k` is fine, but the same expression with runtime `k` is not — keep
  the `const k = 2;` pattern for stack arrays like the forged-witness column.
- `@truncate(v.value)` is the inverse of `F.fromInt(x)`: the tower bit string
  *is* the integer representation, so unpacking a packed value is free and the
  pack equation `v = Σ b_i·fromInt(1<<i)` is a field identity in the standard
  basis (no tower-specific basis math needed).
- Rejection tests over tiny witnesses must break *every* hypercube point:
  a single-cell violation is a point polynomial whose MLE vanishes for most τ in
  a small field, so re-prove over a whole-column violation (`2` in every cell
  of a bit column → booleanness sum = α ≠ 0) for guaranteed rejection.




