# Changelog

All notable changes to this project are documented here. The public API follows
[semantic versioning](https://semver.org/); pre-1.0 minor bumps may introduce
breaking changes.

## [0.2.0] - 2026-08-13

### Added

- `src/binius/clmul.zig`: hardware CLMUL-accelerated carry-less multiply for the
  tower-field `mul`/`mulHi`/`inv` fast path, with runtime detection of
  `pclmulqdq` support and a software fallback. Tables are built lazily on first
  use behind a mutex.
- `docs/binius.md`: a "Memory model (caller-deinit convention)" section
  documenting ownership rules for every public `Proof`, `MerkleTree`, and
  builder helper.
- `CHANGELOG.md` and a "Releases" section in the README.

### Changed

- **Breaking:** the Binius STARK and product-sum argument no longer take a
  comptime column/table cap. The `max_cols` / `max_tables` parameters and the
  `MaxColumns` / `MaxTables` constants are removed; all fixed-size arrays sized
  by the cap are now heap-allocated at the actual column count. Signatures:
  - `BiniusStark(F, E)` (was `BiniusStark(F, E, max_cols)`)
  - `BiniusStarkFri(F, E, log_blowup, num_queries)`
  - `BiniusStarkWith(F, E, CP)`
  - `BiniusArg(F, E)` (was `BiniusArg(F, max_tables)`)
  - `BiniusArgFri(F, E, log_blowup, num_queries)`
  - `BiniusArgWith(F, E, CP)`
- **Memory lifetime:** every public `Proof` now owns its heap memory and exposes
  `deinit(self: *Proof, allocator)`, which the caller must invoke with the same
  allocator passed to `prove` / `proveEval` / `commit`. `MerkleTree` carries its
  own allocator. Inputs passed into the API are always borrowed, and `verify`
  never frees proof memory.
- `arg.Proof.evals` is now `[]EvalProof` (mutable) so nested PCS proofs can be
  released.
- All library tests now run against `std.testing.allocator`, so the suite is
  leak-checked end to end.

### Fixed

- `sumcheck.runRounds` leaked `challenges` whenever a round-consistency check
  failed (`errdefer` does not fire on `return null`); this was the normal
  rejection path for any invalid proof. The buffer is now freed before the
  `return null`.
- `stark.prove` leaked the outer `kernelTables` container on the boundary-pin
  path; the pin-kernel `[][]E` wrapper is now freed after its inner tables are
  moved into the shared table pool.

## [0.1.0] - 2026-08-12

Initial release: M31 DEEP-FRI STARK stack (Fibonacci / Rescue / linear-ML
examples), Binius/BSV binary-field stack over the canonical Wiedemann tower of
GF(2^k) with zero-check STARK, committed-MLE / packed / polylog FRI-Binius PCS,
standalone product-sum argument, and a batched 4-bit adder gadget.
