const std = @import("std");
const zig_stark = @import("zig-stark");
const binius = zig_stark.binius;
const Hash = zig_stark.hash.Hash;

const F = binius.tower.Gf256;
const E = binius.tower.Gf2_128;
const BitPack = binius.bitpack.BitPack(F, E);
const Stark = binius.stark.BiniusStark(F, E);
const CommittedPcs = binius.pcs.CommittedMlePcs(F, E);

/// Monotonic clock in nanoseconds (Linux-only, matching the rest of the repo).
fn now() i128 {
    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec));
}

/// One Merkle-committed root per witness column.
fn commitRoots(allocator: std.mem.Allocator, columns: []const []const F) ![BitPack.num_columns]Hash.Digest {
    var roots: [BitPack.num_columns]Hash.Digest = undefined;
    for (0..BitPack.num_columns) |c| {
        var tree = try CommittedPcs.commit(allocator, columns[c]);
        roots[c] = tree.root();
    }
    return roots;
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const alloc = gpa.allocator();

    // One independent 8-bit value per hypercube point: 16 in a batch.
    const k = 4;
    const n = @as(usize, 1) << @intCast(k);
    const values = try alloc.alloc(BitPack.UInt, n);
    defer alloc.free(values);
    for (0..n) |i| values[i] = @intCast((i * 29 + 7) % 256);

    // Witness: num_bits boolean bit columns + one packed value column.
    const columns = try BitPack.generateWitness(alloc, values);
    defer BitPack.freeWitness(alloc, &columns);

    // Cross-check the witness against a direct bit-sliced computation.
    for (0..n) |p| {
        var got: u128 = 0;
        for (0..BitPack.num_bits) |i| {
            got |= @as(u128, @intCast((values[p] >> @intCast(i)) & 1)) << @intCast(i);
        }
        if (got != BitPack.result(columns[BitPack.colValue()][p])) return error.ClaimMismatch;
    }

    // Boundary pin: pin the packed value of the first instance (point 0) as a
    // public statement, so the verifier enforces the claimed byte.
    var pins: [1]Stark.Pin = undefined;
    pins[0] = .{
        .col = BitPack.colValue(),
        .point = 0,
        .value = F.fromInt(values[0]),
    };

    const t_prove = now();
    const proof = try Stark.prove(alloc, k, &columns, &BitPack.constraints, &pins, "bitpack-batch");
    const prove_ms: f64 = @as(f64, @floatFromInt(now() - t_prove)) / std.time.ns_per_ms;

    const roots = try commitRoots(alloc, &columns);
    const t_verify = now();
    const ok = try Stark.verify(alloc, k, &roots, &BitPack.constraints, &pins, proof, "bitpack-batch");
    const verify_ms: f64 = @as(f64, @floatFromInt(now() - t_verify)) / std.time.ns_per_ms;

    std.debug.print("binius bit-pack gadget batch ({d} values, k={d}, {d}-bit)\n", .{
        n, k, BitPack.num_bits,
    });
    std.debug.print("  columns:    {d}\n", .{BitPack.num_columns});
    std.debug.print("  constraints:{d} (+{d} boundary pins)\n", .{ BitPack.num_constraints, pins.len });
    std.debug.print("  prove:      {d:.2} ms\n", .{prove_ms});
    std.debug.print("  verify:     {d:.2} ms\n", .{verify_ms});
    std.debug.print("  verifier accepted proof: {any}\n", .{ok});
    if (!ok) return error.VerificationFailed;
    std.debug.print("  v0 = {d}; pinned as a boundary assertion\n", .{values[0]});

    // Proof-size breakdown (this PCS opens every hypercube entry, so eval
    // openings dominate — the motivation for a low-degree-test layer).
    const dmax = 2 * k + 1; // pin term: k pin-kernel + 1 witness + k τ-kernel
    const sumcheck_b = @as(usize, k) * (@as(usize, dmax) + 1) * E.SIZE;
    const path_b = k * 32; // one sibling digest per Merkle level
    const evals_b = BitPack.num_columns * n * (F.SIZE + path_b);
    std.debug.print("  sumcheck:   {d} B\n", .{sumcheck_b});
    std.debug.print("  eval opens: {d} B ({d} columns x {d} entries)\n", .{
        evals_b, BitPack.num_columns, n,
    });

    // Flip one packed bit: the committed roots no longer match the proof.
    var bad: [BitPack.num_columns][]F = undefined;
    for (0..BitPack.num_columns) |c| bad[c] = try alloc.dupe(F, columns[c]);
    defer {
        for (bad) |c| alloc.free(c);
    }
    for (0..n) |p| bad[BitPack.colValue()][p] = bad[BitPack.colValue()][p].add(F.one());
    const bad_roots = try commitRoots(alloc, &bad);
    const ok_tampered_root = try Stark.verify(alloc, k, &bad_roots, &BitPack.constraints, &pins, proof, "bitpack-batch");
    std.debug.print("  verifier rejected tampered commitment: {any}\n", .{!ok_tampered_root});
    if (ok_tampered_root) return error.TamperedAccepted;

    // Re-proving over a forged witness whose bit-0 column is 2 everywhere
    // violates booleanness at all hypercube points, giving Σ_x R(x)·β_τ(x) =
    // α ≠ 0 (soundness 1 - 1/|F| in the combination coefficient α).
    var bad_cols: [BitPack.num_columns][]const F = undefined;
    for (0..BitPack.num_columns) |c| bad_cols[c] = bad[c];
    const forged = try Stark.prove(alloc, k, &bad_cols, &BitPack.constraints, &pins, "bitpack-batch");
    const ok_forged = try Stark.verify(alloc, k, &bad_roots, &BitPack.constraints, &pins, forged, "bitpack-batch");
    std.debug.print("  verifier rejected forged witness: {any}\n", .{!ok_forged});
    if (ok_forged) return error.ForgedAccepted;

    // The transcript binds the public input: verifying with any other string
    // re-derives different challenges and must reject.
    const ok_wrong_pub = try Stark.verify(alloc, k, &roots, &BitPack.constraints, &pins, proof, "other-batch");
    std.debug.print("  verifier rejected altered public input: {any}\n", .{!ok_wrong_pub});
    if (ok_wrong_pub) return error.PublicInputNotBound;

    // The pins are public statements too: a wrong pin value re-derives
    // different challenges and must reject.
    var bad_pins = pins;
    bad_pins[0].value = bad_pins[0].value.add(F.one());
    const ok_wrong_pin = try Stark.verify(alloc, k, &roots, &BitPack.constraints, &bad_pins, proof, "bitpack-batch");
    std.debug.print("  verifier rejected altered boundary pin: {any}\n", .{!ok_wrong_pin});
    if (ok_wrong_pin) return error.PinNotBound;
}
