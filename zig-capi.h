/* zig-capi.h — C ABI for the zig-stark Binius zero-check STARK.
 *
 * Instantiation: F = tower.Gf256 (1-byte elements), E = tower.Gf2_128
 * (16-byte elements), PCS = CommittedMlePcs (eval-openings).
 *
 * All byte buffers follow the canonical wire format (docs/wire.md):
 * little-endian; field elements are SIZE bytes; slices are u64-length
 * prefixed; usize is 8 bytes; optionals carry a 1-byte presence flag.
 *   columns:     []const []const F      one 2^k-entry column per witness col
 *   constraints: []const Constraint     { terms: []const { coeff: u8, factors: []const u64 } }
 *   pins:        []const Pin            { col: u64, point: u64, value: u8 }
 *   roots:       []const u8[32]         Merkle roots, one per witness column
 *   proof:       serialized Stark.Proof (the output of zs_binius_prove)
 *
 * Memory: every buffer the library returns is allocated with the
 * `HostAllocator` you passed and must be released with `zs_free` using the
 * same callbacks. Buffers you pass in are borrowed for the duration of the
 * call and never freed.
 *
 * Return codes: 0 ok; -1 generic error; -2 malformed input bytes;
 * -3 out of memory; -4 protocol error.
 */
#ifndef ZIG_CAPI_H
#define ZIG_CAPI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Host memory callbacks. `alloc` returns a block the host can later free with
 * `free` (both receive `ctx`). */
typedef struct {
    void *ctx;
    void *(*alloc)(void *ctx, size_t size);
    void (*free)(void *ctx, void *ptr, size_t size);
} zs_host_allocator;

/* Prove a generic zero-check statement.
 * Returns 0 on success and sets *out_proof/*out_len to a host-allocated
 * serialized proof; the caller releases it with zs_free. */
int32_t zs_binius_prove(
    zs_host_allocator host,
    uint8_t k,
    const uint8_t *columns_ptr, size_t columns_len,
    const uint8_t *constraints_ptr, size_t constraints_len,
    const uint8_t *pins_ptr, size_t pins_len,
    const uint8_t *domain_ptr, size_t domain_len,
    uint8_t **out_proof, size_t *out_len);

/* Verify a serialized proof against the committed roots and statement.
 * Sets *out_ok to 1/0. Returns 0 on success, negative on input error. */
int32_t zs_binius_verify(
    zs_host_allocator host,
    uint8_t k,
    const uint8_t *roots_ptr, size_t roots_len,
    const uint8_t *constraints_ptr, size_t constraints_len,
    const uint8_t *pins_ptr, size_t pins_len,
    const uint8_t *proof_ptr, size_t proof_len,
    const uint8_t *domain_ptr, size_t domain_len,
    int *out_ok);

/* Release a buffer returned by the ABI (use the same HostAllocator). */
void zs_free(zs_host_allocator host, uint8_t *ptr, size_t len);

/* Version / configuration string of this ABI instantiation. */
const char *zs_version(void);

/* ---- wasm-only variants ----------------------------------------------
 * Built when targeting wasm32-freestanding (`zig build wasm`). They use two
 * host-imported functions, `env.zig_stark_malloc(size) -> ptr` and
 * `env.zig_stark_free(ptr, size)`, instead of the HostAllocator struct:
 *
 *   int32_t zs_binius_prove_wm(uint8_t k, const uint8_t *columns, size_t columns_len,
 *       const uint8_t *constraints, size_t constraints_len,
 *       const uint8_t *pins, size_t pins_len,
 *       const uint8_t *domain, size_t domain_len,
 *       uint8_t **out_proof, size_t *out_len);
 *   int32_t zs_binius_verify_wm(uint8_t k, const uint8_t *roots, size_t roots_len,
 *       const uint8_t *constraints, size_t constraints_len,
 *       const uint8_t *pins, size_t pins_len,
 *       const uint8_t *proof, size_t proof_len,
 *       const uint8_t *domain, size_t domain_len, int *out_ok);
 *   int32_t zs_binius_commit_wm(uint8_t k, const uint8_t *columns, size_t columns_len,
 *       uint8_t **out_roots, size_t *out_len);
 *   void    zs_free_wm(uint8_t *ptr, size_t len);
 *
 * Returned buffers are allocated with the imported malloc and released with
 * zs_free_wm. See bindings/js/ for the reference JavaScript wrapper.
 * --------------------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* ZIG_CAPI_H */
