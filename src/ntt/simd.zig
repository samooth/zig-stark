const std = @import("std");
const M31 = @import("../field/m31.zig").M31;
const classic = @import("classic.zig");

/// SIMD butterfly placeholder.
///
/// A true vectorized NTT is not possible over M31 beyond size 2 (the field's
/// multiplicative group has 2-adicity 1). The SIMD-friendly transform on this
/// field is the circle FFT (see `ntt/circle.zig` and `field/m31.zig` Vec8 ops).
/// This module currently delegates to the scalar NTT and is only valid for
/// `a.len <= 2`.
pub fn simdButterfly(a: []M31, invert: bool) void {
    std.debug.assert(a.len <= 2);
    classic.nttClassic(a, invert);
}

test "simd butterfly round-trip (n = 2)" {
    const alloc = std.testing.allocator;
    const input = [_]M31{ M31.fromInt(4), M31.fromInt(1) };
    var work = try alloc.dupe(M31, &input);
    defer alloc.free(work);

    simdButterfly(work, false);
    simdButterfly(work, true);
    try std.testing.expect(work[0].eq(input[0]));
    try std.testing.expect(work[1].eq(input[1]));
}
