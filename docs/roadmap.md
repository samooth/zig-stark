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
  canonical proof serialization, a parallel prover (`core.pool.Pool`, ~4x at 8
  cores), and a C ABI (`src/capi.zig`, `zig-capi.h`) driving a WebAssembly
  binding for browsers (`bindings/js/`) and a native N-API addon for Node
  (`bindings/node/`).
- Toolchain/quality: Zig 0.16.0 stable pinned in CI and a SHA-verified
  `Dockerfile`; 223 tests (207 unit + 16 e2e, leak-checked); published
  benchmarks; Apache-2.0.

The original TODO milestone list is fully implemented; protocol and soundness
details live in `docs/binius.md`, `docs/protocol.md`, and `docs/wire.md`.

## Future work

- **Recursive verification.** Turn the FRI-Binius verifier into an AIR/gadget so
  proofs verify proofs (proof recursion / composition), the natural next step for
  folding schemes.
- **GPU (Phase E, in progress).** Native CUDA acceleration for the server-side
  prover. E0a (toolchain) landed: Zig 0.16 cannot emit nvptx kernels (the LLVM
  backend errors and there is no self-hosted backend), so kernels are CUDA C
  compiled to PTX and loaded via the CUDA Driver API from `src/cuda/` (opt-in,
  CPU fallback when no GPU/driver). E1 landed: the Binius zero-check sum-check
  round runs on the GPU in both single-field `E = F = Gf256` and extension
  `F = Gf16, E = Gf2_128` modes, via a CUDA-free accelerator hook
  (`src/binius/accel.zig`, `GpuMode` auto/on/off; `zig build cuda-gf` +
  `zig build cuda-sumcheck` validate bit-exactness and byte-identical Stark
  proofs). Gf2_128 wins on the GPU for k>=5 (Gf256 for k>=8); per-round
  overhead dominates for small k. E2 landed: the M31 circle FFT
  (`src/cuda/circlefft_gpu.zig`) runs forward/inverse transforms bit-exact with
  `ntt/circle.zig` — the twiddle tree is built with the library's own
  `precomputeTwiddles` and only the butterfly/bit-reversal/(de)interleave layers
  run on the GPU; sizes below lg=3 and missing GPUs fall back to the CPU
  (`zig build cuda-circlefft`, kernels in `src/cuda/kernels/circlefft.cu`).
  Current speedups are modest (1.1-1.3x, kernel-launch bound); the win will
  come from fusing the per-layer launches once NTTE-style batched rotations
  land. E3 landed: the Blake3 Merkle tree builder runs on the GPU via a
  `merkle_commit` hook in `core/merkle/merkle.zig` (`GpuMode` auto/on/off,
  default `auto`, hook null by default so the library stays CPU-only). Only the
  internal `hash2(left,right)` reduce runs on the GPU (`src/cuda/merkle_gpu.zig`
  + `src/cuda/kernels/merkle.cu`, a reference Blake3 compression in CUDA C);
  leaves are still hashed on the CPU. The result is bit-exact with the CPU tree
  at every level for n = 2^0..2^16 (`zig build cuda-merkle`). Unlike E1/E2, the
  naive per-node Blake3 kernel does NOT beat vectorized CPU Blake3 at the sizes
  tested — in ReleaseFast the GPU path is ~10x slower per node (serialization-
  bound: a single Blake3 hash is a short sequential chain), so enabling it
  currently regresses rather than accelerates. The win would need a register-
  optimized / host-pinned Blake3 kernel or a fused multi-node launch; the hook
  and bit-exact path are the integration milestone.
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
