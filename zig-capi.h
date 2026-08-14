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

#ifdef __cplusplus
}
#endif

#endif /* ZIG_CAPI_H */
