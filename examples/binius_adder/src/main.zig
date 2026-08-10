const std = @import("std");
const zig_stark = @import("zig-stark");
const binius = zig_stark.binius;
const Hash = zig_stark.hash.Hash;

const F = binius.tower.Gf256;
const E = binius.tower.Gf2_128;
const Adder = binius.adder.Adder(F, E);
const Stark = binius.stark.BiniusStark(F, E, Adder.num_columns);
const CommittedPcs = binius.pcs.CommittedMlePcs(F, E);

/// Monotonic clock in nanoseconds (Linux-only, matching the rest of the repo).
fn now() i128 {
    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec));
}

/// One Merkle-committed root per witness column.
fn commitRoots(allocator: std.mem.Allocator, columns: []const []const F) ![Adder.num_columns]Hash.Digest {
    var roots: [Adder.num_columns]Hash.Digest = undefined;
    for (0..Adder.num_columns) |c| {
        var tree = try CommittedPcs.commit(allocator, columns[c]);
        roots[c] = tree.root();
    }
    return roots;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    // One independent 4-bit addition per hypercube point: 16 in a batch.
    const k = 4;
    const n = @as(usize, 1) << @intCast(k);
    const x = try alloc.alloc(u4, n);
    defer alloc.free(x);
    const y = try alloc.alloc(u4, n);
    defer alloc.free(y);
    for (0..n) |i| {
        x[i] = @intCast((i * 3 + 5) % 16);
        y[i] = @intCast((i * 7 + 2) % 16);
    }

    const columns = try Adder.generateWitness(alloc, x, y);
    defer Adder.freeWitness(alloc, &columns);

    // The sums cross-check a direct bit-sliced computation.
    const sums = try alloc.alloc(u8, n);
    defer alloc.free(sums);
    Adder.results(x, y, sums);
    for (0..n) |i| {
        if (sums[i] != @as(u8, x[i]) + @as(u8, y[i])) return error.ClaimMismatch;
    }

    // Boundary pins: pin the 5 output bits (s_0..s_3, c_4) of the first
    // instance (point 0), so the verifier enforces the claimed result as a
    // public statement instead of trusting the witness.
    var pins: [Adder.num_bits + 1]Stark.Pin = undefined;
    for (0..Adder.num_bits) |i| {
        pins[i] = .{ .col = Adder.colS(i), .point = 0, .value = F.fromInt((sums[0] >> @intCast(i)) & 1) };
    }
    pins[Adder.num_bits] = .{
        .col = Adder.colC(Adder.num_bits),
        .point = 0,
        .value = F.fromInt((sums[0] >> @intCast(Adder.num_bits)) & 1),
    };

    const t_prove = now();
    const proof = try Stark.prove(alloc, k, &columns, &Adder.constraints, &pins, "adder-batch");
    const prove_ms: f64 = @as(f64, @floatFromInt(now() - t_prove)) / std.time.ns_per_ms;

    const roots = try commitRoots(alloc, &columns);
    const t_verify = now();
    const ok = try Stark.verify(alloc, k, &roots, &Adder.constraints, &pins, proof, "adder-batch");
    const verify_ms: f64 = @as(f64, @floatFromInt(now() - t_verify)) / std.time.ns_per_ms;

    std.debug.print("binius 4-bit ripple-carry adder batch ({d} additions, k={d})\n", .{ n, k });
    std.debug.print("  columns:    {d}\n", .{Adder.num_columns});
    std.debug.print("  constraints:{d} (+{d} boundary pins)\n", .{ Adder.num_constraints, pins.len });
    std.debug.print("  prove:      {d:.2} ms\n", .{prove_ms});
    std.debug.print("  verify:     {d:.2} ms\n", .{verify_ms});
    std.debug.print("  verifier accepted proof: {any}\n", .{ok});
    if (!ok) return error.VerificationFailed;
    std.debug.print("  x0 + y0 = {d} + {d} = {d}; pinned as a boundary assertion\n", .{
        x[0], y[0], sums[0],
    });

    // Proof-size breakdown (this PCS opens every hypercube entry, so eval
    // openings dominate — the motivation for a low-degree-test layer).
    const dmax = 2 * k + 1; // pin term: k pin-kernel + 1 witness + k τ-kernel
    const sumcheck_b = @as(usize, k) * (@as(usize, dmax) + 1) * E.SIZE;
    const path_b = k * 32; // one sibling digest per Merkle level
    const evals_b = Adder.num_columns * n * (F.SIZE + path_b);
    std.debug.print("  sumcheck:   {d} B\n", .{sumcheck_b});
    std.debug.print("  eval opens: {d} B ({d} columns x {d} entries)\n", .{
        evals_b, Adder.num_columns, n,
    });

    // Flip one output bit: the committed roots no longer match the proof.
    var bad: [Adder.num_columns][]F = undefined;
    for (0..Adder.num_columns) |c| bad[c] = try alloc.dupe(F, columns[c]);
    defer {
        for (bad) |c| alloc.free(c);
    }
    // Flip s_1 on every row so the re-proved witness violates the sum
    // constraint at all 16 hypercube points (see the forged-witness check).
    for (0..n) |p| bad[Adder.colS(1)][p] = bad[Adder.colS(1)][p].add(F.one());
    const bad_roots = try commitRoots(alloc, &bad);
    const ok_tampered_root = try Stark.verify(alloc, k, &bad_roots, &Adder.constraints, &pins, proof, "adder-batch");
    std.debug.print("  verifier rejected tampered commitment: {any}\n", .{!ok_tampered_root});
    if (ok_tampered_root) return error.TamperedAccepted;

    // Re-proving over a tampered witness fails the zero-check. A single-cell
    // flip is a point violation whose MLE vanishes for most challenge points τ
    // in a small field, so flip the whole s_1 column: every hypercube point now
    // violates the sum constraint, giving Σ_x R(x)·β_τ(x) = α ≠ 0 (soundness
    // 1 - 1/|F| in the combination coefficient α).
    var bad_cols: [Adder.num_columns][]const F = undefined;
    for (0..Adder.num_columns) |c| bad_cols[c] = bad[c];
    const forged = try Stark.prove(alloc, k, &bad_cols, &Adder.constraints, &pins, "adder-batch");
    const ok_forged = try Stark.verify(alloc, k, &bad_roots, &Adder.constraints, &pins, forged, "adder-batch");
    std.debug.print("  verifier rejected forged witness: {any}\n", .{!ok_forged});
    if (ok_forged) return error.ForgedAccepted;

    // The transcript binds the public input: verifying with any other string
    // re-derives different challenges and must reject.
    const ok_wrong_pub = try Stark.verify(alloc, k, &roots, &Adder.constraints, &pins, proof, "other-batch");
    std.debug.print("  verifier rejected altered public input: {any}\n", .{!ok_wrong_pub});
    if (ok_wrong_pub) return error.PublicInputNotBound;

    // The pins are public statements too: a wrong pin value re-derives
    // different challenges and must reject.
    var bad_pins = pins;
    bad_pins[0].value = bad_pins[0].value.add(F.one());
    const ok_wrong_pin = try Stark.verify(alloc, k, &roots, &Adder.constraints, &bad_pins, proof, "adder-batch");
    std.debug.print("  verifier rejected altered boundary pin: {any}\n", .{!ok_wrong_pin});
    if (ok_wrong_pin) return error.PinNotBound;
}
