const std = @import("std");

pub fn splatVec8(val: u32) @Vector(8, u32) {
    return @as(@Vector(8, u32), @splat(val));
}

pub fn loadVec8(ptr: [*]const u32) @Vector(8, u32) {
    return ptr[0..8].*;
}

pub fn storeVec8(ptr: [*]u32, vec: @Vector(8, u32)) void {
    ptr[0..8].* = vec;
}
