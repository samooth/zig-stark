# Roadmap

## Status

`zig-stark` is a complete dual-stack STARK library in Zig (0.16.0 stable):

- **M31 DEEP-FRI STARK** (`src/m31/`): generic `GenericStark(Air)` over the
  M31/CM31/QM31 tower with circle FFTs, LogUp multiset lookups, and three
  examples (Fibonacci, Rescue, linear ML).
- **Binius zero-check STARK** (`src/binius/`): pluggable committed-MLE PCS
  (`CommittedMlePcs`, `PackedPcs`, polylog `FriPcs`, batched `BatchFriPcs`),
  extension-field `(F, E)` soundness, boundary pins, a gadget library (adder,
  bit-pack, range check, comparison) composable via a comptime constraint DSL,
  and canonical proof serialization.
- Toolchain/quality: Zig 0.16.0 stable pinned in CI and a SHA-verified
  `Dockerfile`; 217 tests (202 unit + 15 e2e, leak-checked); published
  benchmarks; Apache-2.0.

The original TODO milestone list is fully implemented; protocol and soundness
details live in `docs/binius.md`, `docs/protocol.md`, and `docs/wire.md`.

## Future work

- **Recursive verification.** Turn the FRI-Binius verifier into an AIR/gadget so
  proofs verify proofs (proof recursion / composition), the natural next step for
  folding schemes.
- **Parallel prover.** Thread the dominant work — per-column commitments,
  sum-checks, row packing (additive NTT), FRI folds — across cores.
- **Smaller batch openings.** The remaining proof-size gap is the batch-proof
  internals: batched FRI queries (combine `q` queries into one response
  polynomial per layer), a Brakedown-style batched eval sum-check, and
  tower-size-1 packing (see `docs/binius.md` §9).
- **On-chain / script verification (BSV).** The `Gf16`/`Gf256` + `Gf2_128`
  extension mode targets Bitcoin-Script-friendly witnesses; a constrained
  verifier (small RAM, script opcodes) and a fully serialized proof format are
  the concrete deliverables.
- **Monomial-basis additive FFT.** If a monomial representation is ever needed
  on a hot path, a Gao–Mateer additive FFT (monomial basis) would complement the
  novel-basis NTT used by the packing/`FriPcs` today.

Bugs are tracked on GitHub (https://github.com/samooth/zig-stark/issues).
