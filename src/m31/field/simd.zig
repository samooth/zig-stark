const std = @import("std");
const M31 = @import("m31.zig").M31;

pub const FieldVec8 = @Vector(8, u32);

pub fn m31AddVec(a: FieldVec8, b: FieldVec8) FieldVec8 {
    return M31.addVec8(a, b);
}

pub fn m31SubVec(a: FieldVec8, b: FieldVec8) FieldVec8 {
    return M31.subVec8(a, b);
}

pub fn m31MulVec(a: FieldVec8, b: FieldVec8) FieldVec8 {
    return M31.mulVec8(a, b);
}
