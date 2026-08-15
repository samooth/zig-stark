const std = @import("std");

/// Pluggable accelerator hook for the Binius sum-check. The library never
/// depends on CUDA: `sumcheck.zig` calls `gf256_values` (when set) to compute
/// the per-round `values[t]` over Gf256; a CUDA-enabled process registers the
/// implementation at startup. Returning `null` falls back to the CPU path.
///
/// Inputs are flattened into the wire-friendly shapes the GPU kernel consumes:
///   - `cur_flat`: `m·len` bytes — the low byte of each `Gf256.value`.
///   - `coeffs`:   `nterms` bytes (term coefficients, low byte).
///   - `indices`:  concatenated factor column indices per term.
///   - `offsets`:  `nterms + 1` — term `t`'s factors live in
///     `indices[offsets[t]..offsets[t+1])`.
///   - `half`:     `len/2`; the kernel pairs `(2·rest, 2·rest+1)`.
/// The result is `dmax + 1` bytes (the low bytes of `values[t]`), or `null`.
pub const Gf256ValuesFn = *const fn (
    allocator: std.mem.Allocator,
    cur_flat: []const u8,
    len: usize,
    m: usize,
    coeffs: []const u8,
    indices: []const u32,
    offsets: []const u32,
    dmax: usize,
    half: usize,
) anyerror!?[]u8;

/// Registered GPU `values[t]` evaluator for Gf256, or `null` for CPU.
pub var gf256_values: ?Gf256ValuesFn = null;
