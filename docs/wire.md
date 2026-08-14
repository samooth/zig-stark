# Wire format (proof serialization)

`src/core/serialization.zig` gives every proof type in both stacks a canonical
little-endian byte encoding via `serialize(allocator, value)` /
`deserialize(allocator, bytes, T)`. The format is derived entirely from the
compile-time type of the value — no hand-written per-struct code — so all
Binius proofs (`Sumcheck.Proof`, `MlePcs.Proof`, `CommittedMlePcs.Proof`,
`FriPcs.Proof`, `BatchFriPcs.Proof`, `PackedPcs.Proof`, `BiniusArgWith.Proof`,
`BiniusStarkWith.Proof` in both the per-column and batched eval shapes) and
both M31 proofs (`Fri.Proof`, `GenericStark.Proof`) round-trip through the same
two functions.

## Element encoding

| Type | Wire bytes |
|------|-----------|
| Field element (struct with `SIZE`, `toBytes(&[SIZE]u8)`, `fromBytes([SIZE]u8)`) | `SIZE` little-endian bytes |
| `[N]u8` (this is `Hash.Digest = [32]u8`) | the `N` bytes verbatim |
| `[N]T` (other) | the elements in order |
| `[]T` / `[]const T` | `u64` LE length, then the elements |
| unsigned integer | `bits/8` little-endian bytes |
| `?T` | one byte presence flag (`0`/`1`), then `T` |
| struct | fields in declaration order |

The field-element encoding is *exactly* the convention every Fiat-Shamir
transcript in the repo already absorbs (`T.SIZE` little-endian via `toBytes`),
so wire bytes and transcript bytes agree. Widths are comptime-derived, never
hard-coded — in particular `tower.Gf16` is 2 bytes while the script
`field.Gf16` is 1, and `usize` is always 8 bytes.

## Conventions

- **Allocators never cross the wire.** `std.mem.Allocator` fields (embedded by
  the M31 proofs) are skipped on write and restored to the caller's allocator
  on read.
- **`owns_entries` never crosses the wire.** `CommittedMlePcs.Proof` borrows
  its `entries` from the committed table when prover-produced, but a
  deserialized proof owns its copy; the serializer skips the flag and forces it
  to `true` on read so `deinit` frees the reconstructed `entries`.
- **Self-delimiting.** Every variable-length section carries a `u64` length
  prefix; `deserialize` rejects trailing data (`error.TrailingBytes`) and
  truncated input (`error.UnexpectedEnd`).
- **Deterministic.** For a fixed proof the bytes are fixed, pinned by the
  golden test in `serialization.zig`.

## Ownership

A deserialized proof owns its memory exactly like a prover-produced one:
release with the same `deinit(allocator)` using the allocator passed to
`deserialize`. The round-trip e2e tests (`tests/e2e_tests.zig`) prove
`prove -> serialize -> deserialize -> verify` accepts the reconstructed proof
for `CommittedMlePcs`, `BatchFriPcs`, both `BiniusArg` PCS backends, and the
M31 Fibonacci STARK, all leak-free under the testing allocator.

## Out of scope

`src/binius/addfri.zig` proofs carry live `MerkleTree`s and are not wired into
any STARK or PCS, so they are not serialized.
