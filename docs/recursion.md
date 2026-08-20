# Recursive verification — friendly hash study and R0

This document records the design decision for the **recursive verification**
milestone (turning the FRI-Binius verifier into an in-circuit gadget) and the
R0 landing: a **field-friendly hash** that can be computed inside the binary-tower
zero-check STARK.

## Why a friendly hash is needed (the B vs A decision)

A STARK proof of a STARK verifier ("proof recursion") re-executes the verifier
inside the arithmetization. Every hash the verifier calls must therefore be
expressible as field constraints over the witness field.

- **Option A — bit-exact Blake3 + SHA256.** Keeps byte-identity with the current
  proofs but a STARK-friendly Blake3 in-circuit needs carry-propagating integer
  arithmetic (bit-columns + full adders). Per hash that is on the order of
  **40k–70k constraints** (each byte is 8 bits, each round carries across the
  whole integer). A single recursion step calls the transcript + Merkle +
  FRI hashes hundreds of times → **~1M–4.5M constraints per recursion**, and the
  128-bit security target forces a large field. Rejected.
- **Option B — small-field permutation over the tower (chosen).** Replace the
  transcript/Merkle/FRI hashes with a permutation over `Gf2^n` so the S-box is a
  single field multiplication. Per hash drops to **~1k–3k constraints** (see the
  cost model in §5). This breaks byte-identity with current proofs but the
  GPU↔CPU byte-identity of *every other* operation is preserved. It also unlocks
  folding and on-chain BSV verification later. Chosen.

## Hash candidate study (decide-with-data)

Two field-native candidates were compared against the constraints cost model
(per hash, single instance):

| Candidate | S-box per field element | Linear layer | Constraints / hash (order of magnitude) |
|---|---|---|---|
| Blake3 in-circuit (baseline A) | carry-ripple adders over bit columns | bit-column carries | ~40k–70k |
| Keccak-lite (reduced Keccak-f) | AND/XOR/ROT over bits | bit-sliced | ~65k–90k (≈ 5–7 perm × ~13k) |
| **Poseidon2b over `Gf2_64`** | `x^7` (3 squarings + 1 mul) | tower-MDS / O(t) | **~1k–3k** |

**Keccak-lite fails the B requirement**: being bit-oriented it costs ~700
constraints/round and an 80-byte `hash2` needs ~5–7 permutations, landing at the
*same* cost as Blake3-in-circuit — it buys nothing. Only an *algebraic*
permutation over the field (Poseidon) delivers the 2–3 orders of magnitude win.

**Poseidon2b** (ePrint 2025/1893, "Poseidon(2)b: Binary Field Versions of
Poseidon/Poseidon2") is the right fit: it is *designed for Binius*, targets 128
bits, and ships reference parameters + a proof implementation
(`Poseidon-Hash/Poseidon2b`) to mirror bit-exactly. Concrete paper parameters
(Table 1) include `n = 64` with `t = 8`, exactly our tower's `F = Gf2_64`.

## Parameter selection (R0)

| Parameter | Value | Source |
|---|---|---|
| Field `F` | `Gf2_64 = TowerField(6)` | `src/binius/tower.zig` |
| Extension `E` | `Gf2_128 = TowerField(7)` (degree-2 over `Gf2_64`) | soundness |
| State `t` | 8 | paper Table 1 |
| S-box | `x^7` | `d = 7` |
| Full rounds `R_F` | 10 (5 + 5) | paper Table 1 |
| Partial rounds `R_P` | 29 | paper Table 1 |
| Rate `r` / capacity `c` | 4 / 4 (256-bit capacity) | 128-bit security target |
| Digest | 32 bytes = 4 × `Gf2_64` | matches current `[32]u8` |

The constants (round constants `RC`, full matrix `MDS_FULL`, partial matrix
`MDS_PARTIAL`) are transcribed **verbatim** from the reference circuit
`binius_poseidon2b/crates/circuits/src/hades/poseidon2b_x7_64_512.rs`. Its
`BinaryField64b` uses the same Wiedemann-tower bit representation as this repo
(`tower.zig`), so `F.fromInt(u64)` reproduces the same field element. The
reference `plain_permutation` structure is mirrored exactly:

```
state <- M_E · state          (initial linear layer, M_E = MDS_FULL)
for r in 0..(R_F + R_P):
  full:   state <- M_E · (state + rc[i][r])^7          (r < 5 or r >= 34)
  partial:state <- M_P · ((state[0] + rc[0][r])^7, state[1..])   (else)
```

`M_P = 1 + diag(mu)` is the O(t) partial matrix (`y_i = (mu_i+1)·x_i + Σ_j x_j`).

## Sponge / domain (host `recursion/hash.zig`)

- `hashBytes(msg)`: absorb 32-byte (4-element) blocks, zero-pad the final
  partial block, squeeze the first 4 elements of the final state. Empty message
  absorbs one all-zero block.
- `hash2(a, b)`: `hashBytes("zig-stark:pair" · 0^17 ‖ a ‖ b)` — the existing
  domain separator occupies its own aligned rate block, keeping the drop-in
  `core/hash` shape (`Digest = [32]u8`).

This is a **custom sponge** (not the paper's exact fixed-input modes): the
capacity is 256 bits, which gives the 128-bit security target, but the
zero-padding rule means a message whose length is an exact multiple of the rate
and a message with an appended zero block can share a final pad block. For a
fixed-digest random-oracle replacement used in Fiat-Shamir and Merkle
commitments that difference does not threaten the 128-bit collision resistance;
it is documented here as a deliberate, non-standard construction.

## Arithmetization cost (per hash2, 3 permutations)

From the paper's Binius cost model (§6.2, "committed columns" counts; this DSL
has no virtual-column oracle, see §6):

- One permutation: `t·(R_F+1) + R_P = 8·11 + 29 = 117` committed columns in
  the paper's S-box-only layout.
- This implementation commits the **full state at every round** ("row" layout:
  41 states × 8 = 328 columns; 320 constraints) so every constraint stays
  degree ≤ 7 (the S-box) without virtual-column machinery. The `(x+c)^7` binomial
  expands to 8 monomials `c^(7-q)·x^q` (all binomial coefficients are 1 mod 2),
  giving ≈ 8.9k monomials total — versus ≈40k–70k for Blake3-in-circuit.

## Honest divergences

- **Row layout vs virtual columns.** The paper commits only S-box outputs and
  derives states virtually (needs `LinComb`/expression oracle columns). This repo's
  `StarkInner` zero-check sees only committed columns, so the gadget commits
  every round state. More columns, identical polynomial relationship.
- **Custom sponge/padding** (§4) rather than the paper's exact modes.
- **`k + log_blowup <= F.BITS`** is not a concern here: `F = Gf2_64` has 64 bits.
- **First stack exercise with `F.SIZE = 8`** (64-bit witness columns). The
  committed-MLE PCS, Merkle hashing of field elements, and the sum-check
  transcript were all exercised bit-exact in R0 with no non-generic assumptions
  found.
- **Comptime constraint build.** The tower's `mul` dispatches to a runtime
  fast-multiply table (atomics) that is not comptime-safe, so the constraint
  monomial coefficients are multiplied through a local comptime-pure Karatsuba.
  (Superseded by the runtime builder in the final implementation:
  `buildConstraints` constructs the system at runtime, where `mul`/`pow` are
  fast.)

## Validation (R0)

`src/binius/recursion/`

- `poseidon2b.zig`: `PermutationWith(F, E, CP)` gadget — `buildConstraints`
  (runtime) + `generateWitness` + `permutationState` host reference; tests
  assert the witness satisfies every constraint, a STARK round-trip over
  `Gf2_64`/`Gf2_128`, and that the committed output matches the host
  permutation byte-for-byte.
- `hash.zig`: sponge `hashBytes`/`hash2` and known-answer vectors that pin the
  byte-identity surface (if parameters change these break on purpose).

## Roadmap from here

- **R0.5** — switchover: route the transcript (`channel.zig`), `core/hash`
  `hash2`/`hashBytes`, the FRI PCS transcript (`fripcs.zig`), and the sum-check
  transcript (SHA256) through this friendly hash. Migrate byte-fixed tests; the
  proofs' byte-identity changes but GPU↔CPU stays identical.
- **R1** — `Gf2_128` arithmetic as constraints (the verifier's `E` field).
- **R2** — sum-check round gadget + Merkle path gadget.
- **R3** — FRI-Binius PCS verifier gadget.
- **R4** — full `StarkInner.verify` gadget + end-to-end proof-of-verification.

## References & licensing

- Grassi, Khovratovich, Koschatko, Rechberger, Schröppel, Wu. *Poseidon(2)b:
  Binary Field Versions of Poseidon/Poseidon2*. ePrint 2025/1893
  (IACR CIC 2026). https://eprint.iacr.org/2025/1893
- Reference implementation `Poseidon-Hash/Poseidon2b`
  (https://github.com/Poseidon-Hash/Poseidon2b): `binius_poseidon2b` circuit is
  Apache-2.0; `sage-ref` + top-level files are MIT. The transcribed constants in
  `poseidon2b.zig` derive from the `poseidon2b_x7_64_512.rs` circuit.
