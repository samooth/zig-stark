const std = @import("std");

pub fn bitReverse(index: usize, log_n: u32) usize {
    var result: usize = 0;
    var i: u32 = 0;
    var idx = index;
    while (i < log_n) : (i += 1) {
        result = (result << 1) | (idx & 1);
        idx >>= 1;
    }
    return result;
}

pub fn log2Int(comptime T: type, x: T) u32 {
    return @intCast(std.math.log2(x));
}

pub fn nextPowerOfTwo(n: usize) usize {
    if (n == 0) return 1;
    var p: usize = 1;
    while (p < n) p <<= 1;
    return p;
}

pub fn isPowerOfTwo(n: usize) bool {
    return n != 0 and (n & (n - 1)) == 0;
}
