const std = @import("std");
const M31 = @import("../field/m31.zig").M31;
const bit_utils = @import("../utils/bit_utils.zig");

/// Classic radix-2 Cooley-Tukey NTT over M31.
///
/// NOTE: F_(2^31 - 1) has multiplicative-group 2-adicity 1, so primitive
/// roots of unity only exist for sizes 1 and 2. This routine is therefore
/// only valid for `a.len <= 2`. For real transforms on this field use the
/// circle FFT (`ntt/circle.zig`), whose domain has full 2-power structure.
pub fn nttClassic(a: []M31, invert: bool) void {
    const n = a.len;
    std.debug.assert(bit_utils.isPowerOfTwo(n));
    std.debug.assert(n <= 2);

    // Bit-reversal permutation (only meaningful for n == 2; trivial for 1).
    var j: usize = 0;
    for (1..n) |i| {
        var bit = n >> 1;
        while (j & bit != 0) : (bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) std.mem.swap(M31, &a[i], &a[j]);
    }

    // Cooley-Tukey butterflies
    var len: usize = 2;
    while (len <= n) : (len <<= 1) {
        const wlen = if (invert)
            M31.primitiveRootOfUnity(@as(u32, @intCast(len))).inv()
        else
            M31.primitiveRootOfUnity(@as(u32, @intCast(len)));

        var i: usize = 0;
        while (i < n) : (i += len) {
            var w = M31.one();
            for (0..len / 2) |k| {
                const u = a[i + k];
                const v = a[i + k + len / 2].mul(w);
                a[i + k] = u.add(v);
                a[i + k + len / 2] = u.sub(v);
                w = w.mul(wlen);
            }
        }
    }

    if (invert) {
        const n_inv = M31.fromInt(@as(u32, @intCast(n))).inv();
        for (a) |*x| x.* = x.mul(n_inv);
    }
}

pub fn nttForward(a: []M31) void {
    nttClassic(a, false);
}

pub fn nttInverse(a: []M31) void {
    nttClassic(a, true);
}

test "classic NTT round-trip (n = 2)" {
    const alloc = std.testing.allocator;
    const input = [_]M31{ M31.fromInt(3), M31.fromInt(5) };
    var work = try alloc.dupe(M31, &input);
    defer alloc.free(work);

    nttForward(work);
    nttInverse(work);
    try std.testing.expect(work[0].eq(input[0]));
    try std.testing.expect(work[1].eq(input[1]));
}

test "classic NTT forward maps identity transform" {
    // NTT of [a, b] with w = -1 is [a+b, a-b]
    var v = [_]M31{ M31.fromInt(2), M31.fromInt(9) };
    nttForward(&v);
    try std.testing.expect(v[0].eq(M31.fromInt(11)));
    try std.testing.expect(v[1].eq(M31.fromInt(7).neg()));
}
