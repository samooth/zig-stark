const std = @import("std");
const zig_stark = @import("zig-stark");
const binius = zig_stark.binius;
const Hash = zig_stark.hash.Hash;

const F = binius.tower.Gf256;
const E = binius.tower.Gf2_128;
const RangeCheck = binius.rangecheck.RangeCheck(F, E, 4);
const Compare = binius.compare.Compare(F, E, 4);
const Stark = binius.stark.BiniusStark(F, E);
const CommittedPcs = binius.pcs.CommittedMlePcs(F, E);

// Two range-check instances (one per compared value) plus one comparison, all
// in a single proof. The `shiftInto` DSL appends each gadget's constraints with
// remapped column indices, then two monomials per link equate the range-check
// bit columns to the comparison's a/b bit columns, so the range-checked values
// ARE the compared ones: the proof shows a sequence that is strictly increasing
// and bounded in [0, 16).
const num_cols = 2 * RangeCheck.num_columns + Compare.num_columns;
const num_links = 2 * RangeCheck.num_bits;
const num_cons = 2 * RangeCheck.num_constraints + Compare.num_constraints + num_links;
const constraints = blk: {
    var b: binius.constraints.Builder(Stark.Constraint, num_cons, 96) = .{ .mono = undefined };
    binius.constraints.shiftInto(@TypeOf(b), &b, 0, 0, RangeCheck.constraints);
    binius.constraints.shiftInto(@TypeOf(b), &b, RangeCheck.num_constraints, RangeCheck.num_columns, RangeCheck.constraints);
    binius.constraints.shiftInto(@TypeOf(b), &b, 2 * RangeCheck.num_constraints, 2 * RangeCheck.num_columns, Compare.constraints);
    // Link bit i: b_x_i = a_i and b_y_i = b_i (a linear combination per link).
    for (0..RangeCheck.num_bits) |i| {
        const base = 2 * RangeCheck.num_constraints + Compare.num_constraints;
        b.add(base + i, F.one(), &.{i});
        b.add(base + i, F.one(), &.{2 * RangeCheck.num_columns + i});
        b.add(base + RangeCheck.num_bits + i, F.one(), &.{RangeCheck.num_columns + i});
        b.add(base + RangeCheck.num_bits + i, F.one(), &.{2 * RangeCheck.num_columns + Compare.num_bits + i});
    }
    const data = b.finish();
    var out: [num_cons]Stark.Constraint = undefined;
    var off: usize = 0;
    for (0..num_cons) |t| {
        out[t] = .{ .terms = data.mono[off .. off + data.cnt[t]] };
        off += data.cnt[t];
    }
    break :blk out;
};

/// Monotonic clock in nanoseconds (Linux-only, matching the rest of the repo).
fn now() i128 {
    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec));
}

/// One Merkle-committed root per witness column.
fn commitRoots(allocator: std.mem.Allocator, columns: []const []const F) ![num_cols]Hash.Digest {
    var roots: [num_cols]Hash.Digest = undefined;
    for (0..num_cols) |c| {
        var tree = try CommittedPcs.commit(allocator, columns[c]);
        roots[c] = tree.root();
    }
    return roots;
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const alloc = gpa.allocator();

    // One independent step of a strictly increasing bounded sequence per point:
    // instance p proves seq[p] < seq[p+1] and both are in [0, 16).
    const k = 3;
    const n = @as(usize, 1) << @intCast(k);
    const seq = [_]RangeCheck.UInt{ 0, 2, 4, 6, 8, 10, 12, 14, 15 };
    const x = seq[0..n];
    const y = seq[1 .. n + 1];

    // Witness columns: range-check bits/values for x and y, then the compare.
    const rx = try RangeCheck.generateWitness(alloc, x);
    defer RangeCheck.freeWitness(alloc, &rx);
    const ry = try RangeCheck.generateWitness(alloc, y);
    defer RangeCheck.freeWitness(alloc, &ry);
    const cm = try Compare.generateWitness(alloc, x, y);
    defer Compare.freeWitness(alloc, &cm);

    var columns: [num_cols][]F = undefined;
    for (0..RangeCheck.num_columns) |c| columns[c] = rx[c];
    for (0..RangeCheck.num_columns) |c| columns[RangeCheck.num_columns + c] = ry[c];
    for (0..Compare.num_columns) |c| columns[2 * RangeCheck.num_columns + c] = cm[c];

    // Cross-check the witness against direct arithmetic.
    for (0..n) |p| {
        if (!(x[p] < y[p])) return error.NotIncreasing;
        if (x[p] >= 16 or y[p] >= 16) return error.OutOfRange;
        if (RangeCheck.result(columns[RangeCheck.colValue()][p]) != x[p]) return error.BitsMismatch;
        if (Compare.result(x[p], y[p]) != 1) return error.CompareMismatch;
        if (columns[2 * RangeCheck.num_columns + Compare.colLt(0)][p].value != 1) return error.LtMismatch;
    }

    // Public statement: pin the first and last elements of the sequence.
    var pins: [2]Stark.Pin = undefined;
    pins[0] = .{ .col = RangeCheck.colValue(), .point = 0, .value = F.fromInt(seq[0]) };
    pins[1] = .{ .col = RangeCheck.num_columns + RangeCheck.colValue(), .point = n - 1, .value = F.fromInt(seq[n]) };

    const t_prove = now();
    const proof = try Stark.prove(alloc, k, &columns, &constraints, &pins, "rangecmp");
    const prove_ms: f64 = @as(f64, @floatFromInt(now() - t_prove)) / std.time.ns_per_ms;

    const roots = try commitRoots(alloc, &columns);
    const t_verify = now();
    const ok = try Stark.verify(alloc, k, &roots, &constraints, &pins, proof, "rangecmp");
    const verify_ms: f64 = @as(f64, @floatFromInt(now() - t_verify)) / std.time.ns_per_ms;

    std.debug.print("binius range-check + comparison batch ({d} steps, k={d}, [0, 2^{d}))\n", .{
        n, k, RangeCheck.num_bits,
    });
    std.debug.print("  columns:    {d} (2 range checks x {d} + compare x {d})\n", .{
        num_cols, RangeCheck.num_columns, Compare.num_columns,
    });
    std.debug.print("  constraints:{d} (2x{d} + {d} + {d} value links)\n", .{
        num_cons, RangeCheck.num_constraints, Compare.num_constraints, num_links,
    });
    std.debug.print("  prove:      {d:.2} ms\n", .{prove_ms});
    std.debug.print("  verify:     {d:.2} ms\n", .{verify_ms});
    std.debug.print("  verifier accepted proof: {any}\n", .{ok});
    if (!ok) return error.VerificationFailed;
    std.debug.print("  seq[0] = {d}, seq[{d}] = {d} pinned as public inputs\n", .{ seq[0], n, seq[n] });

    // Flip one committed bit: the roots no longer match the proof.
    var bad: [num_cols][]F = undefined;
    for (0..num_cols) |c| bad[c] = try alloc.dupe(F, columns[c]);
    defer {
        for (bad) |c| alloc.free(c);
    }
    bad[Compare.colLt(0)][0] = bad[Compare.colLt(0)][0].add(F.one());
    const bad_roots = try commitRoots(alloc, &bad);
    const ok_tampered_root = try Stark.verify(alloc, k, &bad_roots, &constraints, &pins, proof, "rangecmp");
    std.debug.print("  verifier rejected tampered commitment: {any}\n", .{!ok_tampered_root});
    if (ok_tampered_root) return error.TamperedAccepted;

    // Re-prove over a witness violating the claims: an out-of-range value
    // (v = 16) and an unordered pair (x > y). Both are caught by the zero-check.
    var bad_cols: [num_cols][]F = undefined;
    for (0..num_cols) |c| bad_cols[c] = try alloc.dupe(F, columns[c]);
    defer {
        for (bad_cols) |c| alloc.free(c);
    }
    bad_cols[RangeCheck.colValue()][1] = F.fromInt(16); // first range check, point 1
    for (0..Compare.num_bits) |i| {
        const a = bad_cols[2 * RangeCheck.num_columns + Compare.colA(i)][3];
        bad_cols[2 * RangeCheck.num_columns + Compare.colA(i)][3] = bad_cols[2 * RangeCheck.num_columns + Compare.colB(i)][3];
        bad_cols[2 * RangeCheck.num_columns + Compare.colB(i)][3] = a;
    }
    const forged_roots = try commitRoots(alloc, &bad_cols);
    const forged = try Stark.prove(alloc, k, &bad_cols, &constraints, &pins, "rangecmp");
    const ok_forged = try Stark.verify(alloc, k, &forged_roots, &constraints, &pins, forged, "rangecmp");
    std.debug.print("  verifier rejected forged witness (out-of-range + unordered): {any}\n", .{!ok_forged});
    if (ok_forged) return error.ForgedAccepted;

    // The transcript binds the public inputs: any other string re-derives
    // different challenges and must reject.
    const ok_wrong_pub = try Stark.verify(alloc, k, &roots, &constraints, &pins, proof, "other");
    std.debug.print("  verifier rejected altered public input: {any}\n", .{!ok_wrong_pub});
    if (ok_wrong_pub) return error.PublicInputNotBound;

    // The pins are public too: a wrong pin value must reject.
    var bad_pins = pins;
    bad_pins[0].value = bad_pins[0].value.add(F.one());
    const ok_wrong_pin = try Stark.verify(alloc, k, &roots, &constraints, &bad_pins, proof, "rangecmp");
    std.debug.print("  verifier rejected altered boundary pin: {any}\n", .{!ok_wrong_pin});
    if (ok_wrong_pin) return error.PinNotBound;
}
