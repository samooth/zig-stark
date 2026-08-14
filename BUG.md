# BUG

Confirmed defects found during development, with reproduction notes. Keep the entry
after fixing (strike-through or a note) so the fix commit has a record of what/why.
There are no open defects; reported issues are tracked on GitHub
(https://github.com/samooth/zig-stark/issues).

## Fiat-Shamir challenge sampling is 4-bit for 1-byte fields — FIXED

- **Locations:**
  - `src/binius/sumcheck.zig:63` — `Sumcheck(F).Transcript.absorb`
  - `src/binius/stark.zig:167` — `StarkInner.deriveChallenges` samples τ
  - `src/binius/stark.zig:171` — `StarkInner.deriveChallenges` samples α_t
- **Cause:** all three used `F.fromInt(buf[31] & 0x0f)` when `F.SIZE == 1`, masking the
  sampled byte to 4 bits. Correct for `Gf16` (BITS = 4), but for `Gf256` (BITS = 8) it
  shrank the challenge space to 16 values instead of 256, weakening Fiat-Shamir
  soundness.
- **Repro:** not reachable today — the tower sum-check tests use `Gf16` (mask is correct)
  and `Gf2_32` (SIZE = 4, takes the else branch). Any future use of the sum-check / STARK
  stack over `Gf256` would silently run with 4-bit challenges.
- **Fix (2026-08-10, commit `3878321`):** dropped the `& 0x0f` mask in all
  three sites — `F.fromInt(buf[31])` already masks to `BITS` bits in both
  `TowerField.fromInt` and `BinaryField.fromInt` (`(1 << BITS) - 1`, or `maxInt(u128)`
  for BITS = 128). Gf16 output is bit-for-bit unchanged; Gf256 now uses the full 8-bit
  challenge space. Kept the `fromBytes` branch for larger fields. Added regression tests
  asserting > 16 distinct values over 64 draws for the sum-check transcript and for
  `challengePoint`/`combinationCoeffs` on `Gf256`.
