# BUG

Confirmed defects found during development, with reproduction notes. Keep the entry
after fixing (strike-through or a note) so the fix commit has a record of what/why.

## Fiat-Shamir challenge sampling is 4-bit for 1-byte fields

- **Locations:**
  - `src/binius/sumcheck.zig:66` — `Sumcheck(F).Transcript.absorb`
  - `src/binius/stark.zig:113` — `randomTaus`
  - `src/binius/stark.zig:136` — `combinationCoeffs`
- **Cause:** all three use `F.fromInt(buf[31] & 0x0f)` when `F.SIZE == 1`, masking the
  sampled byte to 4 bits. Correct for `Gf16` (BITS = 4), but for `Gf256` (BITS = 8) it
  shrinks the challenge space to 16 values instead of 256, weakening Fiat-Shamir
  soundness.
- **Repro:** not reachable today — the tower sum-check tests use `Gf16` (mask is correct)
  and `Gf2_32` (SIZE = 4, takes the else branch). Any future use of the sum-check / STARK
  stack over `Gf256` will silently run with 4-bit challenges.
- **Fix suggestion:** sample by bit width, as `AdditiveFri.Transcript` does:
  `F.fromInt(buf[31])` for `SIZE == 1` — `TowerField.fromInt` already masks to `BITS`
  bits (`(1 << BITS) - 1`, or `maxInt(u128)` for BITS = 128). Keep the `fromBytes` branch
  for larger fields.
