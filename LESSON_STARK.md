# LESSON_STARK.md

Session notes on the STARK/circle-FFT mathematics, gathered while replacing the
naive circle FFT with stwo's O(n log n) recursive-fold algorithm in `src/ntt/circle.zig`.

## Why the circle group is needed over M31

- Standard radix-2 NTTs need primitive 2^k-th roots of unity in the field.
  F_(2^31 - 1) has multiplicative group order p - 1 = 2 * 1073741823, i.e.
  2-adicity 1: only sizes 1 and 2 are possible (see `src/ntt/classic.zig`).
- The circle group C = { (x, y) : x^2 + y^2 = 1 } over M31 has order 2^31, giving
  full 2-power structure. This is the STARK-friendly substitute for roots of
  unity — the "circle FFT" is to M31 what an NTT is to a 2-adic field.

## Circle polynomial representation

- A function on a domain of order 2^n that is (x, y) -> A(x) + y * B(x) with
  deg A, B < 2^(n-1) is a "circle polynomial": f(P) = A(x_P) + y_P * B(x_P).
- Coefficients are n in total (A length 2^(n-1), B length 2^(n-1)) matching the
  domain size. The public layout in this repo is A-then-B: `coeffs[0..half]` = A,
  `coeffs[half..n]` = B.

## The Fourier (iterated-pi) basis

- The O(n log n) algorithm does NOT use monomial coefficients. The recursion
  closes only in the basis built from pi(x) = 2x^2 - 1 (the x-coordinate of point
  doubling): a tensor product
  {1, y} ⊗ {1, x} ⊗ {1, pi(x)} ⊗ {1, pi^2(x)} ⊗ ...
- Concretely the basis functions (n = 8) are:
  1, y, x, xy, pi(x), y*pi(x), x*pi(x), xy*pi(x).
- This is exactly stwo's `CircleCoefficients` ("FFT basis ... tensor product of
  the twiddles y, x, pi(x), ..."), stored interleaved as [A0, B0, A1, B1, ...].
  Since A[i] lands at even index 2i and B[i] at odd 2i+1, converting A-then-B to
  interleaved is a trivial `interleave`/`deinterleave`.

## Evaluation by folding (the naive reference)

- f(P) can be computed in O(n) by folding with factors
  [pi^(n-2)(x), ..., pi(x), x, y] (note y is last, and the list is reversed into
  folding order). This mirrors `get_folding_alphas` + `fold` in stwo.
- This fold IS the correct naive reference for the fast FFT in the same basis:
  fast circleFFT output must equal fold at every domain point.

## The fast transform (stwo port)

- Forward (`evaluate`): place interleaved coefficients in a buffer; run line
  butterfly layers largest-to-smallest, then the circle layer (layer 0). Each
  layer uses `butterfly(v0,v1,t)`: tmp = v1*t; v1 = v0 - tmp; v0 = v0 + tmp.
- Inverse (`interpolate`): same layers in reverse order (circle first, then lines
  small-to-large) using `ibutterfly(v0,v1,itw)`: tmp = v0; v0 = tmp + v1;
  v1 = (tmp - v1) * itw, with **inverse twiddles**, then multiply by inv(2^n).
- Base cases are hardcoded for log_size 1 and 2 (they divide by y, so they are
  written out rather than using the generic twiddle machinery).
- Twiddles: `slow_precompute_twiddles` builds a tree from the half-coset — each
  level k takes the bit-reversed x-coordinates of the first 2^(k-1) points of the
  current (doubling) coset, then doubles the coset; a trailing padding value
  rounds the length to a power of two. The per-layer slices are read off the back
  of this buffer (`domain_line_twiddles_from_tree`).

## Domains, cosets, and the identity point

- A valid circle domain is `half_coset ++ half_coset.conjugate()`, where the
  half-coset is a coset `C + <G_n>` with C outside the order-2^n subgroup. The
  canonic choice is the "half-odds" coset: initial = G^(2^(30-n)), step =
  G^(2^(32-n)) in index space.
- The half-odds coset deliberately excludes the identity (y = 0). Interpolation
  divides by y, so a domain containing the identity (like a plain subgroup, which
  `CircleDomain.standard` produces) breaks the algorithm. This forced the API
  change: the FFT now takes a `CircleCoset` half-coset and derives the full
  domain as coset ++ conjugate.
- The conjugate of a coset is `-initial - <step>`: negate both offset and step.

## Generator conventions (a subtle, real bug)

- stwo's circle generator is (2, 1268011823); this repo's is (1268011823, 2).
  They are NOT the same point. generator().neg() = (1268011823, -2) is equivalent
  to stwo's generator up to an element of order 4 that vanishes under every power
  used by the domain (all exponents >= 2, i.e. log_size <= 28).
- Consequence: the canonic domain's *point set* is generator-independent, but the
  *traversal order* is not. Using the un-negated generator produces a
  half-rotated ordering that silently breaks the FFT's eval-vs-fold check. Using
  generator().neg() consistently (domain + twiddles) is what makes everything
  line up. The lesson: fix the exact generator a reference algorithm uses before
  assuming your own generator behaves identically.

## Ordering: bit-reversed in, natural out

- The FFT layers emit values in bit-reversed order (this is stwo's
  `BitReversedOrder`). Bit-reversing the buffer once recovers natural order
  `evals[i] = f(domain[i])`. The public API in this repo does that final pass and
  documents the output as natural.
- Input to the inverse transform must be bit-reversed first, then the layers run.

## Validation methodology that worked

1. Python simulation of the whole algorithm (twiddles, layers, fold, base cases)
   checked: fast == fold at every domain point, interpolate(evaluate(c)) == c
   exactly, for lg = 1..8.
2. Root-cause of a failing run: the sim was rebuilt with the wrong generator;
   the mismatch was a fixed cyclic shift, a strong hint the domain order rather
   than arithmetic was at fault.
3. Ported to Zig, then cross-checked a fixed input byte-for-byte against the
   Python reference — caught a test that had fed the interleaved sequence as
   A-then-B.
4. Known-value tests (constant, f = x, f = y in the FFT basis) give ground truth
   independent of the fold reference.
