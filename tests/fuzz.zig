//! Randomized property stress for the Binius gadgets. Every iteration:
//!   - builds a random valid witness, proves and verifies it (must accept), and
//!   - tampers a byte of the *serialized proof* and verifies again (must
//!     reject — the verifier's sum-check / Merkle checks are exact, so a
//!     modified proof is rejected deterministically, unlike a witness tamper
//!     whose zero-check can miss a single-point violation in a small field).
//! Runs under the leak-checking DebugAllocator; `zig build fuzz` invokes it.

const std = @import("std");
const zs = @import("zig-stark");

const F = zs.binius.tower.Gf256;
const E = zs.binius.tower.Gf256; // single-field for speed; structure is identical
const Hash = zs.hash.Hash;
const Ser = zs.core.serialization;

const Stark = zs.binius.stark.BiniusStark(F, E);
const CommittedPcs = zs.binius.pcs.CommittedMlePcs(F, E);

const Rng = std.Random.DefaultPrng;

/// Prove the witness, commit the roots, and verify. Returns accept/reject.
fn proveVerify(
    alloc: std.mem.Allocator,
    k: usize,
    columns: []const []const F,
    constraints: []const Stark.Constraint,
) !bool {
    const roots = try alloc.alloc(Hash.Digest, columns.len);
    defer alloc.free(roots);
    for (0..columns.len) |c| {
        var tree = try CommittedPcs.commit(alloc, columns[c]);
        defer tree.deinit();
        roots[c] = tree.root();
    }
    var proof = try Stark.prove(alloc, k, columns, constraints, &.{}, "fuzz");
    defer proof.deinit(alloc);
    return try Stark.verify(alloc, k, roots, constraints, &.{}, proof, "fuzz");
}

/// The valid witness must be accepted.
fn expectAccept(alloc: std.mem.Allocator, k: usize, columns: []const []const F, constraints: []const Stark.Constraint) !void {
    if (!try proveVerify(alloc, k, columns, constraints)) return error.FuzzValidRejected;
}

/// A proof with one flipped byte must be rejected (deterministic: the sum-check
/// and Merkle checks fail on any modified value).
fn expectRejectTamperedProof(alloc: std.mem.Allocator, k: usize, columns: []const []const F, constraints: []const Stark.Constraint) !void {
    const roots = try alloc.alloc(Hash.Digest, columns.len);
    defer alloc.free(roots);
    for (0..columns.len) |c| {
        var tree = try CommittedPcs.commit(alloc, columns[c]);
        defer tree.deinit();
        roots[c] = tree.root();
    }
    var proof = try Stark.prove(alloc, k, columns, constraints, &.{}, "fuzz");
    defer proof.deinit(alloc);

    const bytes = try Ser.serialize(alloc, proof);
    defer alloc.free(bytes);
    const tampered = try alloc.dupe(u8, bytes);
    defer alloc.free(tampered);
    tampered[bytes.len / 2] ^= 0x01;

    var rt = try Ser.deserialize(alloc, tampered, Stark.Proof);
    defer rt.deinit(alloc);
    if (try Stark.verify(alloc, k, roots, constraints, &.{}, rt, "fuzz")) return error.FuzzTamperedAccepted;
}

/// RangeCheck: valid values in [0, 2^m).
fn roundRange(alloc: std.mem.Allocator, rnd: std.Random) !void {
    const m = 3;
    const k = 3;
    const n: usize = @as(usize, 1) << @intCast(k);
    const RC = zs.binius.rangecheck.RangeCheck(F, E, m);

    var vals: [n]RC.UInt = undefined;
    for (&vals) |*v| v.* = @intCast(rnd.int(u8) % 8);

    const cols = try RC.generateWitness(alloc, &vals);
    defer RC.freeWitness(alloc, &cols);
    const cols_slice: []const []const F = cols[0..];

    try expectAccept(alloc, k, cols_slice, RC.constraints[0..]);
    try expectRejectTamperedProof(alloc, k, cols_slice, RC.constraints[0..]);
}

/// Compare: random pairs with x < y.
fn roundCompare(alloc: std.mem.Allocator, rnd: std.Random) !void {
    const m = 3;
    const k = 3;
    const n: usize = @as(usize, 1) << @intCast(k);
    const Cmp = zs.binius.compare.Compare(F, E, m);

    var x: [n]Cmp.UInt = undefined;
    var y: [n]Cmp.UInt = undefined;
    for (0..n) |i| {
        const a = rnd.int(u8) % 8;
        const b = rnd.int(u8) % 8;
        x[i] = @intCast(@min(a, b));
        y[i] = @intCast(@max(a, b));
        if (x[i] == y[i]) y[i] = @intCast(@mod(@as(u8, y[i]) + 1, 8)); // keep strictly less
    }

    const cols = try Cmp.generateWitness(alloc, &x, &y);
    defer Cmp.freeWitness(alloc, &cols);
    const cols_slice: []const []const F = cols[0..];

    try expectAccept(alloc, k, cols_slice, Cmp.constraints[0..]);
    try expectRejectTamperedProof(alloc, k, cols_slice, Cmp.constraints[0..]);
}

/// Adder: random 4-bit pairs.
fn roundAdder(alloc: std.mem.Allocator, rnd: std.Random) !void {
    const k = 3;
    const n: usize = @as(usize, 1) << @intCast(k);
    const Adder = zs.binius.adder.Adder(F, E);

    const x = try alloc.alloc(u4, n);
    defer alloc.free(x);
    const y = try alloc.alloc(u4, n);
    defer alloc.free(y);
    for (0..n) |i| {
        x[i] = @intCast(rnd.int(u8) % 16);
        y[i] = @intCast(rnd.int(u8) % 16);
    }

    const cols = try Adder.generateWitness(alloc, x, y);
    defer Adder.freeWitness(alloc, &cols);
    const cols_slice: []const []const F = cols[0..];

    try expectAccept(alloc, k, cols_slice, Adder.constraints[0..]);
    try expectRejectTamperedProof(alloc, k, cols_slice, Adder.constraints[0..]);
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const alloc = gpa.allocator();
    defer {
        const check = gpa.deinit();
        if (check != .ok) @panic("fuzz: memory leaks detected");
    }

    const iters: usize = 2000;
    var prng = Rng.init(0x5eed_c0de);
    const rnd = prng.random();

    for (0..iters) |_| {
        try roundRange(alloc, rnd);
        try roundCompare(alloc, rnd);
        try roundAdder(alloc, rnd);
    }
    std.debug.print("fuzz: {d} iterations x (RangeCheck, Compare, Adder) OK, no leaks\n", .{iters});
}
